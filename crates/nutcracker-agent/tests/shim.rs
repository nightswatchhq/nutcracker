//! The local shim, end to end against an in-process provider.
//!
//! The provider here is the real `InMemoryStore`, so these exercise the actual sealing, indexing,
//! narrowing and decryption path — not a mock of it.

use nutcracker_agent::{
    tool_definitions,
    tools::{Embedder, Memory},
    transport::{ProviderTransport, SealedSearch, SealedWrite, TransportError},
    MemoryTools,
};
use nutcracker_crypto::{NamespaceHandle, RootKey, SealedItem};
use nutcracker_store::{Candidate, InMemoryStore, MemoryStore, StoreError, StoredItem};
use std::cell::RefCell;
use std::rc::Rc;

/// Every byte the provider was ever handed. Shared with the test so the "never sees plaintext"
/// claim can be checked against what actually crossed the boundary, rather than asserted.
type Wire = Rc<RefCell<Vec<Vec<u8>>>>;

/// A provider that is the real store, reached in process.
#[derive(Default)]
struct LocalProvider {
    store: InMemoryStore,
    seen: Wire,
}

impl ProviderTransport for LocalProvider {
    fn write(&mut self, r: SealedWrite) -> Result<(), TransportError> {
        // Record everything that crossed the wire: ciphertext, nonces, wrapped key, tokens.
        let mut seen = self.seen.borrow_mut();
        seen.push(r.sealed.ciphertext.clone());
        seen.push(r.sealed.nonce.to_vec());
        seen.push(r.sealed.wrapped_key.clone());
        seen.push(r.sealed.wrap_nonce.to_vec());
        for t in &r.tokens {
            seen.push(t.0.to_vec());
        }
        seen.push(r.item_id.as_bytes().to_vec());
        seen.push(r.namespace.0.to_vec());
        drop(seen);
        self.store
            .put(
                &r.namespace,
                StoredItem {
                    item_id: r.item_id,
                    sealed: r.sealed,
                    tokens: r.tokens,
                    mode: r.mode,
                    expires_at: r.expires_at,
                },
            )
            .map_err(|e| TransportError::Http {
                status: 507,
                body: e.to_string(),
            })
    }

    fn read(&mut self, ns: &NamespaceHandle, id: &str) -> Result<SealedItem, TransportError> {
        self.store.get(ns, id).map_err(|e| match e {
            StoreError::NotFound => TransportError::NotFound,
            other => TransportError::Http {
                status: 500,
                body: other.to_string(),
            },
        })
    }

    fn search(&mut self, r: SealedSearch) -> Result<Vec<Candidate>, TransportError> {
        Ok(self.store.search(&r.namespace, &r.tokens, r.limit))
    }

    fn forget(&mut self, ns: &NamespaceHandle, id: &str) -> Result<bool, TransportError> {
        Ok(self.store.forget(ns, id))
    }
}

/// A deterministic stand-in for a real local embedding model: a bag-of-characters vector. Crude,
/// but it puts similar strings near each other, which is all these tests need.
struct CharEmbedder;

impl Embedder for CharEmbedder {
    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0f32; 64];
        for b in text.to_lowercase().bytes() {
            v[(b % 64) as usize] += 1.0;
        }
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1.0);
        v.iter().map(|x| x / norm).collect()
    }
}

fn tools() -> MemoryTools<LocalProvider, CharEmbedder> {
    MemoryTools::new(
        RootKey::from_bytes([11u8; 32]),
        LocalProvider::default(),
        Some(CharEmbedder),
    )
}

#[test]
fn the_four_tools_take_text_because_the_shim_is_local() {
    let defs = tool_definitions();
    let names: Vec<&str> = defs
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "memory.write",
            "memory.search",
            "memory.read",
            "memory.forget"
        ]
    );

    // The write tool asks for `text`, not ciphertext. That is only safe because this process holds
    // the key and runs on the user's machine.
    let write = &defs[0]["inputSchema"]["properties"];
    assert!(write.get("text").is_some());
    assert!(
        write.get("ciphertext").is_none(),
        "an agent must never be asked to hand over ciphertext"
    );
}

#[test]
fn a_memory_can_be_written_and_read_back() {
    let mut t = tools();
    t.write("notes", "m1", "we chose postgres over sqlite", None)
        .unwrap();
    assert_eq!(
        t.read("notes", "m1").unwrap().text,
        "we chose postgres over sqlite"
    );
}

/// The property the whole architecture exists for, checked against the bytes that actually
/// crossed the boundary rather than asserted in prose.
#[test]
fn the_provider_never_receives_the_plaintext() {
    let wire: Wire = Rc::new(RefCell::new(Vec::new()));
    let provider = LocalProvider {
        store: InMemoryStore::new(),
        seen: Rc::clone(&wire),
    };
    let mut t = MemoryTools::new(
        RootKey::from_bytes([11u8; 32]),
        provider,
        Some(CharEmbedder),
    );

    const SECRET: &[u8] = b"my passphrase is hunter2";
    t.write("notes", "m1", "my passphrase is hunter2", None)
        .unwrap();
    t.write("notes", "m2", "my passphrase is hunter2", None)
        .unwrap();

    let seen = wire.borrow();
    assert!(!seen.is_empty(), "sanity: the wire recorded something");

    // No fragment of the secret appears anywhere the provider could see it.
    for window in 6..=SECRET.len() {
        for chunk in SECRET.windows(window) {
            for buf in seen.iter() {
                assert!(
                    !buf.windows(chunk.len()).any(|w| w == chunk),
                    "a {window}-byte fragment of the plaintext crossed the wire"
                );
            }
        }
    }

    // And two identical plaintexts must not produce identical ciphertexts, or the provider learns
    // that the same thing was written twice.
    let ciphertexts: Vec<&Vec<u8>> = seen.iter().filter(|b| b.len() > SECRET.len()).collect();
    assert!(ciphertexts.len() >= 2);
    assert_ne!(
        ciphertexts[0], ciphertexts[1],
        "identical plaintexts must seal differently"
    );
}

#[test]
fn search_finds_a_related_memory_and_ranks_it() {
    let mut t = tools();
    t.write(
        "notes",
        "db",
        "we chose postgres over sqlite for the sink",
        None,
    )
    .unwrap();
    t.write("notes", "lunch", "sandwiches at the cafe on tuesday", None)
        .unwrap();

    let hits: Vec<Memory> = t
        .search("notes", "we chose postgres over sqlite for the sink", 5)
        .unwrap();
    assert!(!hits.is_empty(), "the matching memory must come back");
    assert_eq!(hits[0].item_id, "db");
    assert!(hits[0].shared_bands > 0);
}

/// Found by running a provider on a second machine and reading its storage: everything was
/// opaque except the item id, sitting there in plain text. Callers name things descriptively —
/// `sofia-lease-renewal` would tell a provider everything the encryption was hiding.
#[test]
fn a_descriptive_item_id_never_reaches_the_provider() {
    let wire: Wire = Rc::new(RefCell::new(Vec::new()));
    let provider = LocalProvider {
        store: InMemoryStore::new(),
        seen: Rc::clone(&wire),
    };
    let mut t = MemoryTools::new(
        RootKey::from_bytes([11u8; 32]),
        provider,
        Some(CharEmbedder),
    );

    t.write("notes", "sofia-lease-renewal", "renews in March", None)
        .unwrap();

    let seen = wire.borrow();
    for buf in seen.iter() {
        for chunk in b"sofia-lease-renewal".windows(5) {
            assert!(
                !buf.windows(chunk.len()).any(|w| w == chunk),
                "a fragment of the item id crossed the wire"
            );
        }
    }
    drop(seen);
    // And it still round-trips under the caller's own name.
    assert_eq!(
        t.read("notes", "sofia-lease-renewal").unwrap().text,
        "renews in March"
    );
}

/// The blinded id must be stable across key rotation, or revoking an agent orphans every item.
#[test]
fn a_blinded_id_survives_key_rotation() {
    let mut t = tools();
    t.write("notes", "named", "before rotation", None).unwrap();
    t.rotate();
    // The item cannot be *decrypted* after rotation (that is the point of rotation), but it must
    // still be addressable — otherwise rewrapping it would be impossible.
    assert!(
        t.forget("notes", "named").unwrap(),
        "still addressable by the same name"
    );
}

#[test]
fn namespaces_do_not_leak_into_each_other() {
    let mut t = tools();
    t.write("work", "a", "the deploy key rotates monthly", None)
        .unwrap();
    assert!(
        t.read("personal", "a").is_err(),
        "a different namespace must not resolve it"
    );
}

#[test]
fn forget_removes_it() {
    let mut t = tools();
    t.write("notes", "m1", "temporary thought", None).unwrap();
    assert!(t.forget("notes", "m1").unwrap());
    assert!(t.read("notes", "m1").is_err());
    assert!(!t.forget("notes", "m1").unwrap(), "already gone");
}

/// Without a local embedder, search must fail loudly rather than quietly sending the query
/// somewhere to be embedded.
#[test]
fn search_without_an_embedder_refuses_rather_than_leaking_the_query() {
    struct NoEmbedder;
    impl Embedder for NoEmbedder {
        fn embed(&self, _: &str) -> Vec<f32> {
            unreachable!("must not be called")
        }
    }
    let mut t: MemoryTools<LocalProvider, NoEmbedder> = MemoryTools::new(
        RootKey::from_bytes([1u8; 32]),
        LocalProvider::default(),
        None,
    );

    t.write("notes", "m1", "still storable", None).unwrap();
    assert_eq!(
        t.read("notes", "m1").unwrap().text,
        "still storable",
        "read still works"
    );
    assert!(
        t.search("notes", "anything", 5).is_err(),
        "search must refuse"
    );
}

/// After rotation, items written under the old generation no longer decrypt. They are not lost —
/// they need rewrapping — but the shim must skip them rather than hand the agent rubbish.
#[test]
fn candidates_that_do_not_decrypt_are_skipped_not_surfaced() {
    let mut t = tools();
    t.write("notes", "old", "written before the rotation", None)
        .unwrap();
    t.rotate();
    t.write("notes", "new", "written before the rotation", None)
        .unwrap();

    let hits = t
        .search("notes", "written before the rotation", 10)
        .unwrap();
    assert_eq!(hits.len(), 1, "only the current generation decrypts");
    assert_eq!(hits[0].item_id, "new");
}

/// The half the provider cannot do. Bucket collisions are a coarse hint — roughly 3% of returned
/// candidates are unrelated at the default parameters — so the provider's ordering must not be
/// what reaches the agent. This test failed to exist until a real MCP session returned an
/// unrelated memory as a match.
#[test]
fn candidates_are_re_ranked_locally_not_served_in_provider_order() {
    let mut t = tools();
    t.write(
        "notes",
        "match",
        "postgres postgres postgres postgres",
        None,
    )
    .unwrap();
    t.write("notes", "unrelated", "zzz qqq zzz qqq zzz qqq", None)
        .unwrap();

    let hits = t
        .search("notes", "postgres postgres postgres postgres", 5)
        .unwrap();
    assert!(!hits.is_empty());
    assert_eq!(
        hits[0].item_id, "match",
        "the closest memory must come first"
    );
    assert!(
        hits[0].score > 0.9,
        "an near-identical query should score high: {}",
        hits[0].score
    );
    if hits.len() > 1 {
        assert!(
            hits[0].score > hits[1].score,
            "results must be ordered by local similarity, not by the provider's bucket count"
        );
    }
}

/// A zero-magnitude embedding must not produce NaN, because NaN in a sort comparator silently
/// yields a nonsense ordering rather than an error.
#[test]
fn an_empty_query_does_not_produce_a_nan_ordering() {
    let mut t = tools();
    t.write("notes", "a", "something", None).unwrap();
    let hits = t.search("notes", "", 5).unwrap();
    assert!(hits.iter().all(|h| !h.score.is_nan()), "no NaN scores");
}

#[test]
fn search_respects_the_limit_after_local_ranking() {
    let mut t = tools();
    for i in 0..12 {
        t.write(
            "notes",
            &format!("m{i}"),
            "postgres postgres postgres",
            None,
        )
        .unwrap();
    }
    assert_eq!(
        t.search("notes", "postgres postgres postgres", 3)
            .unwrap()
            .len(),
        3
    );
}
