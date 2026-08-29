//! The provider-side store.
//!
//! Everything here runs on the **provider**, and the notable thing about it is how little it can
//! do. It holds opaque ciphertext grouped by an opaque namespace handle, indexed by opaque bucket
//! tokens. It has no key material, no plaintext, no embeddings and no user identities, and the
//! type signatures in this module are the enforcement: there is no way to hand this store a
//! plaintext even by accident, because no function accepts one.
//!
//! Search is a set intersection over bucket tokens, ranked by how many bands match. The provider
//! returns candidates; the client decrypts them and does the real ranking. See `docs/design.md`.

use std::collections::{BTreeMap, HashMap, HashSet};

use nutcracker_crypto::{BucketToken, NamespaceHandle, SealedItem};

pub mod schema;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum StoreError {
    #[error("item not found")]
    NotFound,
    #[error("namespace is at its committed capacity of {0} items")]
    AtCapacity(u64),
}

/// How an item was indexed. Recorded per item because a namespace containing a single
/// plaintext-vector item is no longer end-to-end encrypted, and the store must be able to say so
/// rather than let the claim quietly rot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IndexMode {
    /// Keyed bucket tokens. The default; the provider learns bucket occupancy and nothing more.
    BlindIndex,
    /// The client asked for plaintext vectors. Must be named explicitly at write time.
    PlaintextVectors,
}

/// What a provider stores for one item. Every field is opaque to it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredItem {
    pub item_id: String,
    pub sealed: SealedItem,
    pub tokens: Vec<BucketToken>,
    pub mode: IndexMode,
    /// Unix seconds. `None` means keep until forgotten.
    pub expires_at: Option<u64>,
}

/// A search hit: an item and how many bands it shared with the query.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub item_id: String,
    pub sealed: SealedItem,
    pub shared_bands: usize,
}

/// Counters a provider reports on-chain. Self-reported and unprovable; see the contract.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Usage {
    pub writes: u128,
    pub reads: u128,
    pub searches: u128,
    pub forgets: u128,
}

/// The provider-side contract. Deliberately small.
pub trait MemoryStore {
    fn put(&mut self, ns: &NamespaceHandle, item: StoredItem) -> Result<(), StoreError>;
    fn get(&mut self, ns: &NamespaceHandle, item_id: &str) -> Result<SealedItem, StoreError>;
    /// Candidates sharing at least one bucket token, best first. Never more than `limit`.
    fn search(
        &mut self,
        ns: &NamespaceHandle,
        tokens: &[BucketToken],
        limit: usize,
    ) -> Vec<Candidate>;
    /// Returns whether anything was actually removed. A provider that bills for deletion and
    /// removes nothing is committing ordinary fraud and no store can prevent it; this at least
    /// makes the local truth unambiguous.
    fn forget(&mut self, ns: &NamespaceHandle, item_id: &str) -> bool;
    /// Drops expired items. Returns how many.
    fn gc(&mut self, now: u64) -> usize;
    fn usage(&self) -> Usage;
    /// True when every item in the namespace was written under the blind index, i.e. the
    /// namespace can still honestly be described as end-to-end encrypted.
    fn is_e2e(&self, ns: &NamespaceHandle) -> bool;
}

/// Reference implementation. The Postgres one in `schema` uses the same semantics; this is where
/// they are actually tested.
#[derive(Default)]
pub struct InMemoryStore {
    items: HashMap<NamespaceHandle, BTreeMap<String, StoredItem>>,
    capacity: HashMap<NamespaceHandle, u64>,
    usage: Usage,
}

/// Everything a provider holds, in a form it can write to disk. Still entirely opaque: this is
/// ciphertext and bucket tokens, and a snapshot file leaks exactly what the running process does.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub items: Vec<(NamespaceHandle, Vec<StoredItem>)>,
    pub capacity: Vec<(NamespaceHandle, u64)>,
    pub usage: Usage,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A durable-enough provider: snapshot after each mutation, load at start.
    ///
    /// Not Postgres, and it should not pretend to be — `schema` holds the real thing. This exists
    /// so a personal provider survives a restart, which is the difference between a demo and
    /// something somebody would keep their notes in.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            items: self
                .items
                .iter()
                .map(|(ns, m)| (ns.clone(), m.values().cloned().collect()))
                .collect(),
            capacity: self.capacity.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            usage: self.usage,
        }
    }

    pub fn restore(snap: Snapshot) -> Self {
        let mut s = Self::new();
        for (ns, items) in snap.items {
            let e = s.items.entry(ns).or_default();
            for i in items {
                e.insert(i.item_id.clone(), i);
            }
        }
        s.capacity = snap.capacity.into_iter().collect();
        s.usage = snap.usage;
        s
    }

    /// Sets the item cap a provider committed to on-chain for this namespace.
    pub fn set_capacity(&mut self, ns: &NamespaceHandle, max_items: u64) {
        self.capacity.insert(ns.clone(), max_items);
    }

    pub fn len(&self, ns: &NamespaceHandle) -> usize {
        self.items.get(ns).map_or(0, |m| m.len())
    }

    pub fn is_empty(&self, ns: &NamespaceHandle) -> bool {
        self.len(ns) == 0
    }
}

impl MemoryStore for InMemoryStore {
    fn put(&mut self, ns: &NamespaceHandle, item: StoredItem) -> Result<(), StoreError> {
        let entry = self.items.entry(ns.clone()).or_default();
        if let Some(&cap) = self.capacity.get(ns) {
            // An overwrite of an existing id is not growth.
            if !entry.contains_key(&item.item_id) && entry.len() as u64 >= cap {
                return Err(StoreError::AtCapacity(cap));
            }
        }
        entry.insert(item.item_id.clone(), item);
        self.usage.writes += 1;
        Ok(())
    }

    fn get(&mut self, ns: &NamespaceHandle, item_id: &str) -> Result<SealedItem, StoreError> {
        let out = self
            .items
            .get(ns)
            .and_then(|m| m.get(item_id))
            .map(|i| i.sealed.clone())
            .ok_or(StoreError::NotFound);
        if out.is_ok() {
            self.usage.reads += 1;
        }
        out
    }

    fn search(
        &mut self,
        ns: &NamespaceHandle,
        tokens: &[BucketToken],
        limit: usize,
    ) -> Vec<Candidate> {
        self.usage.searches += 1;
        let query: HashSet<&BucketToken> = tokens.iter().collect();
        let Some(items) = self.items.get(ns) else {
            return Vec::new();
        };

        let mut hits: Vec<Candidate> = items
            .values()
            .filter_map(|item| {
                let shared = item.tokens.iter().filter(|t| query.contains(t)).count();
                (shared > 0).then(|| Candidate {
                    item_id: item.item_id.clone(),
                    sealed: item.sealed.clone(),
                    shared_bands: shared,
                })
            })
            .collect();

        // Most shared bands first. Ties break on item id so results are stable rather than
        // dependent on iteration order — an unstable ranking is miserable to debug and makes the
        // client's own ordering non-reproducible.
        hits.sort_by(|a, b| {
            b.shared_bands
                .cmp(&a.shared_bands)
                .then(a.item_id.cmp(&b.item_id))
        });
        hits.truncate(limit);
        hits
    }

    fn forget(&mut self, ns: &NamespaceHandle, item_id: &str) -> bool {
        let removed = self
            .items
            .get_mut(ns)
            .is_some_and(|m| m.remove(item_id).is_some());
        // Counted whether or not anything was there: the user asked, and the count is meant to
        // reflect requests billed, not a flattering subset of them.
        self.usage.forgets += 1;
        removed
    }

    fn gc(&mut self, now: u64) -> usize {
        let mut dropped = 0;
        for items in self.items.values_mut() {
            let before = items.len();
            items.retain(|_, i| i.expires_at.is_none_or(|e| e > now));
            dropped += before - items.len();
        }
        dropped
    }

    fn usage(&self) -> Usage {
        self.usage
    }

    fn is_e2e(&self, ns: &NamespaceHandle) -> bool {
        self.items
            .get(ns)
            .is_none_or(|m| m.values().all(|i| i.mode == IndexMode::BlindIndex))
    }
}
