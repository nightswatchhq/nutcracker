//! Client-side cryptography for nutcracker: envelope encryption and the keyed blind index.
//!
//! Everything here runs on the **client**. The provider sees ciphertext and opaque bucket tokens
//! and holds no key material at any point. See `docs/design.md`.
//!
//! # A warning that belongs at the top
//!
//! This is unreviewed cryptographic code. Every primitive is a standard one from RustCrypto —
//! XChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256 — and **nothing here invents a construction**,
//! which is the least a reference implementation owes you. It has not been audited. Treat it as a
//! demonstration of the design in `docs/design.md`, not as something to put a stranger's private
//! notes into.
//!
//! # What leaks
//!
//! Stated plainly, because the whole point of the design is that this list is short and honest:
//!
//! - **Sizes.** Ciphertext length reveals plaintext length. Not padded.
//! - **Not the item name.** Item ids are blinded by the shim before they reach a provider, and the
//!   caller's own name is sealed inside the payload. This was not true until a provider was run on
//!   a second machine and its storage read: everything was opaque except `item_id`, sitting there
//!   in plain text. Callers name things descriptively.
//! - **Counts and timing.** How many items a namespace holds and when they were touched.
//! - **Bucket occupancy.** Which of `2^band_bits` buckets a namespace occupies per band, and which
//!   bucket a query touched. Bucket tokens are HMACs under the namespace key, so they are not
//!   comparable across namespaces and reveal nothing without that key.
//!
//! It does **not** leak the embedding vector, which is the thing that makes plaintext-vector
//! designs a false claim to end-to-end encryption.

pub mod blind_index;
pub mod envelope;

pub use blind_index::{BlindIndex, BucketToken, IndexParams};
pub use envelope::{ContentKey, EnvelopeError, NamespaceHandle, NamespaceKey, RootKey, SealedItem};
