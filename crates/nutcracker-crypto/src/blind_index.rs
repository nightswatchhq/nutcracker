//! The keyed blind index: searchable memory that does not hand the provider a copy of it.
//!
//! # Why this exists
//!
//! `memory.search` needs the provider to narrow a namespace to a candidate set. The obvious way is
//! to store each item's embedding in the clear beside its ciphertext and let the provider run
//! nearest-neighbour over the vectors. That works beautifully and **it is not end-to-end
//! encrypted**: text embeddings are not one-way, and a provider holding `(opaque blob, vector)`
//! holds an approximate copy of the memory. See `docs/design.md`.
//!
//! # The construction
//!
//! Standard SimHash LSH with banding, keyed so that buckets are meaningless without the namespace
//! key. Nothing novel; the only design choice is *keying* it and being explicit about the leak.
//!
//! 1. Derive `bands × band_bits` random hyperplanes deterministically from the namespace key.
//! 2. Sign the embedding against each hyperplane to get one bit per hyperplane.
//! 3. Split the bit string into `bands` groups of `band_bits`.
//! 4. HMAC each `(band index, band bits)` under the namespace key to get an opaque token.
//!
//! The provider indexes items by token and, for a query, returns items sharing at least one token.
//! The client decrypts the candidates and does the fine ranking itself.
//!
//! # What the provider learns
//!
//! Which of `2^band_bits` buckets a namespace occupies in each band, and which buckets a query
//! touched. Because tokens are HMACs under the namespace key, the same vector in two namespaces
//! produces unrelated tokens, and a provider holding tokens for a namespace it has no key for
//! learns nothing transferable.
//!
//! It does not learn the vector. That is the whole difference.
//!
//! # The knob
//!
//! More `bands` means better recall and more buckets revealed. Larger `band_bits` means each
//! bucket is more selective — fewer false candidates to download, but a finer-grained fact about
//! the namespace disclosed. Tighten it far enough and this degrades toward pure client-side
//! search; loosen it far enough and it approaches handing over the vector.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::envelope::NamespaceKey;

type HmacSha256 = Hmac<Sha256>;

/// An opaque bucket identifier. This is what actually goes to the provider.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct BucketToken(pub [u8; 16]);

impl BucketToken {
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// The privacy/recall knob. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexParams {
    /// Number of independent bands. More bands, better recall, more buckets revealed.
    pub bands: usize,
    /// Bits per band. More bits, more selective buckets, finer-grained disclosure.
    pub band_bits: usize,
}

impl Default for IndexParams {
    /// 8 bands of 4 bits, chosen on measurement rather than on instinct.
    ///
    /// This was 8x8, on the reasoning that fewer buckets means less disclosure and that is the
    /// right direction for a privacy product. Two things were wrong with that.
    ///
    /// **The disclosure is `bands x band_bits`**, which 8x4 halves to 32 bits per item. The other
    /// number, how many unrelated items come back as candidates, is *bandwidth*: the client
    /// decrypts and re-ranks, so an extra candidate costs a fetch and tells the provider nothing
    /// the bucket token had not. If anything it is cover. Optimising it was optimising the cheap
    /// axis by spending the expensive one.
    ///
    /// **And it interacts with centring.** Since `nutcracker-agent` subtracts the model's shared
    /// direction before hashing, the hyperplanes are no longer half-wasted on a component every
    /// vector has, and a coarser band is enough. Measured on real `nomic-embed-text` embeddings,
    /// 48 sentences over 12 topics (`nutcracker-crypto/examples/real_embeddings.rs`):
    ///
    /// | | recall | candidates | bits/item |
    /// |---|---|---|---|
    /// | as-is 8x8 (the old default) | 46% | 22% | 64 |
    /// | centred 8x8 | **17%** | 3% | 64 |
    /// | centred 8x4 | **67%** | 36% | 32 |
    ///
    /// Read the middle row. Shipping centring while leaving this at 8x8 gave 17% recall - worse
    /// than doing neither - and that is exactly what shipped for an hour before this changed. The
    /// two are one decision and were briefly treated as two.
    fn default() -> Self {
        Self {
            bands: 8,
            band_bits: 4,
        }
    }
}

impl IndexParams {
    /// Bits of information a single band discloses about an item, ignoring correlation.
    pub fn bits_disclosed_per_band(&self) -> usize {
        self.band_bits
    }

    /// Total hyperplanes, and so the cost of indexing one item.
    pub fn hyperplanes(&self) -> usize {
        self.bands * self.band_bits
    }
}

/// A namespace's blind index. Deterministic given the namespace key and params, so the same client
/// on a different device reproduces identical tokens without any shared state.
pub struct BlindIndex {
    key: [u8; 32],
    params: IndexParams,
    /// `hyperplanes[i]` is one pseudo-random unit-ish vector, expanded lazily per dimension.
    seed: [u8; 32],
}

impl BlindIndex {
    pub fn new(ns: &NamespaceKey, params: IndexParams) -> Self {
        let mut h = Sha256::new();
        h.update(b"nutcracker:lsh:v1");
        h.update(ns.as_bytes());
        let seed: [u8; 32] = h.finalize().into();
        Self {
            key: *ns.as_bytes(),
            params,
            seed,
        }
    }

    /// Deterministic pseudo-random component of hyperplane `plane` at dimension `dim`.
    ///
    /// Derived rather than stored: an embedding may have 1536 dimensions and 64 hyperplanes, and
    /// materialising 98k floats per namespace to hash a single vector would be silly.
    fn component(&self, plane: usize, dim: usize) -> f32 {
        let mut h = Sha256::new();
        h.update(self.seed);
        h.update((plane as u32).to_be_bytes());
        h.update((dim as u32).to_be_bytes());
        let d: [u8; 32] = h.finalize().into();
        // Map the first four bytes to (-1, 1). Uniform, not Gaussian — for sign-based LSH the
        // sign of the dot product is what matters and uniform components are standard practice.
        let v = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
        (v as f64 / u32::MAX as f64 * 2.0 - 1.0) as f32
    }

    /// The signature bit for one hyperplane: the sign of the dot product.
    fn bit(&self, plane: usize, embedding: &[f32]) -> bool {
        let mut acc = 0f64;
        for (dim, &x) in embedding.iter().enumerate() {
            acc += f64::from(self.component(plane, dim)) * f64::from(x);
        }
        acc >= 0.0
    }

    /// The bucket tokens for an embedding. These are what the provider stores or searches by.
    pub fn tokens(&self, embedding: &[f32]) -> Vec<BucketToken> {
        let mut out = Vec::with_capacity(self.params.bands);
        for band in 0..self.params.bands {
            let mut bits: u64 = 0;
            for b in 0..self.params.band_bits {
                let plane = band * self.params.band_bits + b;
                if self.bit(plane, embedding) {
                    bits |= 1 << b;
                }
            }
            let mut mac =
                HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
            mac.update(b"nutcracker:bucket:v1");
            mac.update(&(band as u32).to_be_bytes());
            mac.update(&bits.to_be_bytes());
            let tag = mac.finalize().into_bytes();
            let mut t = [0u8; 16];
            t.copy_from_slice(&tag[..16]);
            out.push(BucketToken(t));
        }
        out
    }

    /// How many bands two embeddings share. The provider computes this over tokens without ever
    /// seeing an embedding; it is exposed here so the client can reason about recall.
    pub fn shared_bands(&self, a: &[f32], b: &[f32]) -> usize {
        let ta = self.tokens(a);
        let tb = self.tokens(b);
        ta.iter().zip(tb.iter()).filter(|(x, y)| x == y).count()
    }

    pub fn params(&self) -> IndexParams {
        self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::RootKey;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn ns(seed: u8, name: &str) -> NamespaceKey {
        RootKey::from_bytes([seed; 32]).namespace_key(name, 0)
    }

    fn random_vec(rng: &mut StdRng, dims: usize) -> Vec<f32> {
        (0..dims).map(|_| rng.gen_range(-1.0..1.0)).collect()
    }

    /// A near-duplicate is a small perturbation of the original.
    fn perturb(rng: &mut StdRng, v: &[f32], scale: f32) -> Vec<f32> {
        v.iter().map(|x| x + rng.gen_range(-scale..scale)).collect()
    }

    /// Pinned to the measurement, not to taste.
    ///
    /// The default was 8x8 on the instinct that fewer buckets is more private. It is not: the
    /// disclosure is `bands x band_bits`, and with centring in front of it 8x8 collapses recall to
    /// 17% while 8x4 gives 67% at *half* the per-item disclosure. If someone changes this back,
    /// they should have a newer measurement than `examples/real_embeddings.rs`, and this test is
    /// where they say so.
    #[test]
    fn the_default_is_the_configuration_that_was_measured_best() {
        let p = IndexParams::default();
        assert_eq!((p.bands, p.band_bits), (8, 4));
        assert_eq!(
            p.hyperplanes(),
            32,
            "per-item disclosure is bands x band_bits"
        );
    }

    #[test]
    fn tokens_are_deterministic() {
        let idx = BlindIndex::new(&ns(1, "notes"), IndexParams::default());
        let v = vec![0.1, -0.4, 0.9, 0.2];
        assert_eq!(idx.tokens(&v), idx.tokens(&v));
    }

    #[test]
    fn there_is_one_token_per_band() {
        let p = IndexParams {
            bands: 5,
            band_bits: 4,
        };
        let idx = BlindIndex::new(&ns(1, "notes"), p);
        assert_eq!(idx.tokens(&[0.3, 0.7, -0.2]).len(), 5);
        assert_eq!(p.hyperplanes(), 20);
    }

    /// The property the whole scheme rests on: similar things collide, dissimilar things mostly
    /// do not. Without this it is not an index, it is a hash.
    #[test]
    fn near_duplicates_share_far_more_bands_than_unrelated_vectors() {
        let idx = BlindIndex::new(&ns(1, "notes"), IndexParams::default());
        let mut rng = StdRng::seed_from_u64(42);

        let mut near_total = 0usize;
        let mut far_total = 0usize;
        const TRIALS: usize = 60;

        for _ in 0..TRIALS {
            let base = random_vec(&mut rng, 64);
            let near = perturb(&mut rng, &base, 0.05);
            let far = random_vec(&mut rng, 64);
            near_total += idx.shared_bands(&base, &near);
            far_total += idx.shared_bands(&base, &far);
        }

        let near_avg = near_total as f64 / TRIALS as f64;
        let far_avg = far_total as f64 / TRIALS as f64;
        assert!(
            near_avg > far_avg * 3.0,
            "near-duplicates must collide far more often: near={near_avg:.2} far={far_avg:.2}"
        );
        assert!(
            near_avg > 4.0,
            "recall too low to be useful: {near_avg:.2} of 8 bands"
        );
    }

    /// THE privacy property. The same vector in two namespaces must produce unrelated tokens, or
    /// a provider could correlate users, which is precisely the metadata leak the design exists
    /// to avoid.
    #[test]
    fn the_same_vector_in_two_namespaces_produces_unrelated_tokens() {
        let v = vec![0.4, -0.1, 0.8, 0.3, -0.6];
        let a = BlindIndex::new(&ns(1, "notes"), IndexParams::default()).tokens(&v);
        let b = BlindIndex::new(&ns(2, "notes"), IndexParams::default()).tokens(&v);
        let shared = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
        assert_eq!(shared, 0, "tokens must not be comparable across namespaces");
    }

    /// Rotating the namespace key must reindex, not silently keep working — otherwise a revoked
    /// agent's stale tokens would still match.
    #[test]
    fn rotating_the_namespace_key_changes_every_token() {
        let root = RootKey::from_bytes([9u8; 32]);
        let v = vec![0.2, 0.5, -0.3, 0.1];
        let g0 =
            BlindIndex::new(&root.namespace_key("notes", 0), IndexParams::default()).tokens(&v);
        let g1 =
            BlindIndex::new(&root.namespace_key("notes", 1), IndexParams::default()).tokens(&v);
        assert_eq!(g0.iter().zip(g1.iter()).filter(|(a, b)| a == b).count(), 0);
    }

    /// Tokens are HMAC outputs: fixed width regardless of the embedding, so they leak nothing
    /// about dimensionality or magnitude.
    #[test]
    fn tokens_reveal_nothing_about_the_vectors_shape() {
        let idx = BlindIndex::new(&ns(1, "notes"), IndexParams::default());
        let short = idx.tokens(&[1.0, 2.0]);
        let long = idx.tokens(&vec![0.5f32; 1536]);
        assert_eq!(short.len(), long.len());
        assert!(short.iter().all(|t| t.0.len() == 16));
        assert!(long.iter().all(|t| t.0.len() == 16));
    }

    /// The knob has to actually move. Tightening the parameters must reduce collisions.
    #[test]
    fn more_bits_per_band_means_more_selective_buckets() {
        let key = ns(1, "notes");
        let mut rng = StdRng::seed_from_u64(7);
        let base = random_vec(&mut rng, 64);
        let near = perturb(&mut rng, &base, 0.05);

        let loose = BlindIndex::new(
            &key,
            IndexParams {
                bands: 8,
                band_bits: 2,
            },
        );
        let tight = BlindIndex::new(
            &key,
            IndexParams {
                bands: 8,
                band_bits: 16,
            },
        );

        assert!(
            loose.shared_bands(&base, &near) >= tight.shared_bands(&base, &near),
            "more bits per band must be at least as selective"
        );
    }

    #[test]
    fn an_empty_embedding_does_not_panic() {
        let idx = BlindIndex::new(&ns(1, "notes"), IndexParams::default());
        assert_eq!(idx.tokens(&[]).len(), 8);
    }
}
