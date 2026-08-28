//! The provider-side semantics, tested against the reference store.

use nutcracker_crypto::{BlindIndex, BucketToken, IndexParams, NamespaceHandle, RootKey};
use nutcracker_store::{InMemoryStore, IndexMode, MemoryStore, StoreError, StoredItem};

fn handle(seed: u8, name: &str) -> NamespaceHandle {
    RootKey::from_bytes([seed; 32]).namespace_handle(name)
}

fn item(id: &str, tokens: Vec<BucketToken>, mode: IndexMode, expires: Option<u64>) -> StoredItem {
    let ns = RootKey::from_bytes([1u8; 32]).namespace_key("n", 0);
    StoredItem {
        item_id: id.to_string(),
        sealed: ns.seal(id, format!("contents of {id}").as_bytes()).unwrap(),
        tokens,
        mode,
        expires_at: expires,
    }
}

fn tok(n: u8) -> BucketToken {
    BucketToken([n; 16])
}

#[test]
fn a_stored_item_round_trips_and_stays_sealed() {
    let mut s = InMemoryStore::new();
    let ns = handle(1, "notes");
    s.put(&ns, item("a", vec![tok(1)], IndexMode::BlindIndex, None))
        .unwrap();
    let sealed = s.get(&ns, "a").unwrap();
    // The store returns ciphertext. It never had anything else.
    assert!(!sealed.ciphertext.windows(8).any(|w| w == b"contents"));
}

#[test]
fn namespaces_are_isolated() {
    let mut s = InMemoryStore::new();
    let a = handle(1, "notes");
    let b = handle(2, "notes");
    s.put(&a, item("x", vec![tok(1)], IndexMode::BlindIndex, None))
        .unwrap();
    assert_eq!(s.get(&b, "x"), Err(StoreError::NotFound));
    assert!(
        s.search(&b, &[tok(1)], 10).is_empty(),
        "a token must not match across namespaces"
    );
}

#[test]
fn search_ranks_by_shared_bands_and_breaks_ties_deterministically() {
    let mut s = InMemoryStore::new();
    let ns = handle(1, "notes");
    s.put(
        &ns,
        item(
            "three",
            vec![tok(1), tok(2), tok(3)],
            IndexMode::BlindIndex,
            None,
        ),
    )
    .unwrap();
    s.put(
        &ns,
        item("one-b", vec![tok(1)], IndexMode::BlindIndex, None),
    )
    .unwrap();
    s.put(
        &ns,
        item("one-a", vec![tok(2)], IndexMode::BlindIndex, None),
    )
    .unwrap();
    s.put(&ns, item("none", vec![tok(9)], IndexMode::BlindIndex, None))
        .unwrap();

    let hits = s.search(&ns, &[tok(1), tok(2), tok(3)], 10);
    assert_eq!(hits.len(), 3, "the non-matching item must not be returned");
    assert_eq!(hits[0].item_id, "three");
    assert_eq!(hits[0].shared_bands, 3);
    assert_eq!(hits[1].item_id, "one-a");
    assert_eq!(hits[2].item_id, "one-b");
    assert_eq!(
        s.search(&ns, &[tok(1), tok(2), tok(3)], 10),
        hits,
        "stable across identical queries"
    );
}

#[test]
fn search_respects_the_limit() {
    let mut s = InMemoryStore::new();
    let ns = handle(1, "notes");
    for i in 0..10 {
        s.put(
            &ns,
            item(&format!("i{i}"), vec![tok(1)], IndexMode::BlindIndex, None),
        )
        .unwrap();
    }
    assert_eq!(s.search(&ns, &[tok(1)], 3).len(), 3);
}

#[test]
fn forget_actually_removes_and_reports_honestly() {
    let mut s = InMemoryStore::new();
    let ns = handle(1, "notes");
    s.put(&ns, item("a", vec![tok(1)], IndexMode::BlindIndex, None))
        .unwrap();
    assert!(s.forget(&ns, "a"), "removed");
    assert_eq!(s.get(&ns, "a"), Err(StoreError::NotFound));
    assert!(
        s.search(&ns, &[tok(1)], 10).is_empty(),
        "its buckets went with it"
    );
    assert!(
        !s.forget(&ns, "a"),
        "nothing left to remove: say so rather than claim success"
    );
}

/// Deletion is counted whether or not anything was there. The count reflects requests billed, not
/// a flattering subset of them.
#[test]
fn forget_is_counted_even_when_it_removes_nothing() {
    let mut s = InMemoryStore::new();
    s.forget(&handle(1, "notes"), "never-existed");
    assert_eq!(s.usage().forgets, 1);
}

#[test]
fn expired_items_are_collected() {
    let mut s = InMemoryStore::new();
    let ns = handle(1, "notes");
    s.put(&ns, item("keep", vec![tok(1)], IndexMode::BlindIndex, None))
        .unwrap();
    s.put(
        &ns,
        item("go", vec![tok(1)], IndexMode::BlindIndex, Some(100)),
    )
    .unwrap();
    assert_eq!(s.gc(50), 0, "not yet expired");
    assert_eq!(s.gc(101), 1);
    assert_eq!(s.len(&ns), 1);
    assert!(s.get(&ns, "keep").is_ok());
}

#[test]
fn capacity_is_enforced_but_overwrites_are_not_growth() {
    let mut s = InMemoryStore::new();
    let ns = handle(1, "notes");
    s.set_capacity(&ns, 2);
    s.put(&ns, item("a", vec![tok(1)], IndexMode::BlindIndex, None))
        .unwrap();
    s.put(&ns, item("b", vec![tok(1)], IndexMode::BlindIndex, None))
        .unwrap();
    assert_eq!(
        s.put(&ns, item("c", vec![tok(1)], IndexMode::BlindIndex, None)),
        Err(StoreError::AtCapacity(2))
    );
    // Rewriting an existing id must still work at capacity, or a full namespace becomes read-only.
    s.put(&ns, item("a", vec![tok(2)], IndexMode::BlindIndex, None))
        .unwrap();
}

/// The claim has to be able to become false, or it is not a claim.
#[test]
fn one_plaintext_vector_item_voids_the_e2e_claim_for_the_whole_namespace() {
    let mut s = InMemoryStore::new();
    let ns = handle(1, "notes");
    s.put(&ns, item("a", vec![tok(1)], IndexMode::BlindIndex, None))
        .unwrap();
    assert!(s.is_e2e(&ns));
    s.put(
        &ns,
        item("b", vec![tok(1)], IndexMode::PlaintextVectors, None),
    )
    .unwrap();
    assert!(!s.is_e2e(&ns), "a single named-mode item voids it");
    s.forget(&ns, "b");
    assert!(s.is_e2e(&ns), "and removing it restores the claim");
}

#[test]
fn usage_counts_each_operation() {
    let mut s = InMemoryStore::new();
    let ns = handle(1, "notes");
    s.put(&ns, item("a", vec![tok(1)], IndexMode::BlindIndex, None))
        .unwrap();
    let _ = s.get(&ns, "a");
    s.search(&ns, &[tok(1)], 10);
    s.forget(&ns, "a");
    let u = s.usage();
    assert_eq!((u.writes, u.reads, u.searches, u.forgets), (1, 1, 1, 1));
}

/// End to end against the real crypto: seal, index, store, search, retrieve, decrypt.
#[test]
fn a_real_memory_survives_the_whole_round_trip() {
    let root = RootKey::from_bytes([5u8; 32]);
    let nsk = root.namespace_key("notes", 0);
    let ns = root.namespace_handle("notes");
    let idx = BlindIndex::new(&nsk, IndexParams::default());
    let mut s = InMemoryStore::new();

    let embedding: Vec<f32> = (0..64).map(|i| (i as f32 * 0.037).sin()).collect();
    let plaintext = b"we chose postgres over sqlite for the sink";
    s.put(
        &ns,
        StoredItem {
            item_id: "m1".into(),
            sealed: nsk.seal("m1", plaintext).unwrap(),
            tokens: idx.tokens(&embedding),
            mode: IndexMode::BlindIndex,
            expires_at: None,
        },
    )
    .unwrap();

    let query: Vec<f32> = embedding.iter().map(|x| x + 0.01).collect();
    let hits = s.search(&ns, &idx.tokens(&query), 5);
    assert_eq!(hits.len(), 1, "the memory should be retrieved");
    assert_eq!(
        nsk.open(&hits[0].item_id, &hits[0].sealed).unwrap(),
        plaintext
    );
}
