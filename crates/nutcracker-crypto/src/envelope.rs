//! The three-layer key hierarchy.
//!
//! ```text
//! user root key            held by the user, never sent
//!   └── namespace key      wraps content keys; one per namespace
//!         └── content key  one per item; encrypts the item
//! ```
//!
//! Three layers rather than two exist for exactly one reason: **revocation must not mean
//! re-encrypting everything.** Rotating a namespace key rewraps the content keys, which is small
//! and fast. A two-layer scheme would require re-encrypting every memory the user ever wrote,
//! which nobody does, which means in practice nobody revokes.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("decryption failed: wrong key, or the ciphertext or its associated data was altered")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("malformed sealed item")]
    Malformed,
}

/// Held by the user and never transmitted. Losing it loses the memory; that is what user-held
/// means, and any provider-side recovery is a provider-side copy of the key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; 32]);

/// Wraps content keys for one namespace. Rotating this is how an agent is revoked.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NamespaceKey([u8; 32]);

/// One per item. Never reused across items, so a compromised item cannot decrypt its neighbours.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ContentKey([u8; 32]);

/// What the provider actually stores. Opaque to it in its entirety.
#[derive(Debug, Clone, PartialEq)]
pub struct SealedItem {
    /// The item, under its content key.
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    /// The content key, under the namespace key. Rewrapped on rotation; the ciphertext is not
    /// touched, which is the entire point of the middle layer.
    pub wrapped_key: Vec<u8>,
    pub wrap_nonce: [u8; 24],
}

fn derive(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}

fn seal(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 24]), EnvelopeError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| EnvelopeError::Encrypt)?;
    Ok((ct, nonce.into()))
}

fn open(key: &[u8; 32], ct: &[u8], nonce: &[u8; 24], aad: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload { msg: ct, aad },
        )
        .map_err(|_| EnvelopeError::Decrypt)
}

impl RootKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn generate() -> Self {
        use rand_core::RngCore;
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }

    /// Derives a namespace key. `generation` is the rotation counter: bumping it produces a
    /// completely different key, which is how revocation works.
    pub fn namespace_key(&self, namespace: &str, generation: u32) -> NamespaceKey {
        let mut info = Vec::with_capacity(namespace.len() + 24);
        info.extend_from_slice(b"nutcracker:ns:v1:");
        info.extend_from_slice(namespace.as_bytes());
        info.push(0);
        info.extend_from_slice(&generation.to_be_bytes());
        NamespaceKey(derive(&self.0, &info))
    }
}

/// The opaque handle a provider uses to group one namespace's items.
///
/// The provider needs *something* to group by, or it cannot serve a namespace at all. It must not
/// be the namespace name, which would tell it what the memory is about, and it must not be derived
/// from the namespace *key*, which rotates — a rotating handle would orphan every stored item on
/// revocation.
///
/// So: derived from the root key and the name, stable across generations. The provider learns that
/// a set of items belong together, which is unavoidable, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NamespaceHandle(pub [u8; 16]);

impl NamespaceHandle {
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl RootKey {
    /// Stable across key rotations, by construction. See [`NamespaceHandle`].
    pub fn namespace_handle(&self, namespace: &str) -> NamespaceHandle {
        let mut info = Vec::with_capacity(namespace.len() + 24);
        info.extend_from_slice(b"nutcracker:handle:v1:");
        info.extend_from_slice(namespace.as_bytes());
        let full = derive(&self.0, &info);
        let mut h = [0u8; 16];
        h.copy_from_slice(&full[..16]);
        NamespaceHandle(h)
    }
}

impl NamespaceKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Seals an item under a fresh content key, then wraps that key under this namespace key.
    ///
    /// `item_id` is bound in as associated data on both layers, so a provider cannot move a
    /// ciphertext to a different id and have it still decrypt. Without that, "delete item X" could
    /// be answered by relabelling item Y.
    pub fn seal(&self, item_id: &str, plaintext: &[u8]) -> Result<SealedItem, EnvelopeError> {
        use rand_core::RngCore;
        let mut ck = [0u8; 32];
        OsRng.fill_bytes(&mut ck);

        let (ciphertext, nonce) = seal(&ck, plaintext, item_id.as_bytes())?;
        let (wrapped_key, wrap_nonce) = seal(&self.0, &ck, item_id.as_bytes())?;
        ck.zeroize();

        Ok(SealedItem {
            ciphertext,
            nonce,
            wrapped_key,
            wrap_nonce,
        })
    }

    pub fn open(&self, item_id: &str, item: &SealedItem) -> Result<Vec<u8>, EnvelopeError> {
        let ck = open(
            &self.0,
            &item.wrapped_key,
            &item.wrap_nonce,
            item_id.as_bytes(),
        )?;
        let ck: [u8; 32] = ck.try_into().map_err(|_| EnvelopeError::Malformed)?;
        let out = open(&ck, &item.ciphertext, &item.nonce, item_id.as_bytes());
        let mut ck = ck;
        ck.zeroize();
        out
    }

    /// Rewraps an item's content key under a new namespace key. **The ciphertext is untouched.**
    /// This is what makes rotation cheap enough that people will actually do it.
    pub fn rewrap(
        &self,
        new: &NamespaceKey,
        item_id: &str,
        item: &SealedItem,
    ) -> Result<SealedItem, EnvelopeError> {
        let ck = open(
            &self.0,
            &item.wrapped_key,
            &item.wrap_nonce,
            item_id.as_bytes(),
        )?;
        let (wrapped_key, wrap_nonce) = seal(&new.0, &ck, item_id.as_bytes())?;
        Ok(SealedItem {
            ciphertext: item.ciphertext.clone(),
            nonce: item.nonce,
            wrapped_key,
            wrap_nonce,
        })
    }
}

impl ContentKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> RootKey {
        RootKey::from_bytes([7u8; 32])
    }

    #[test]
    fn a_sealed_item_round_trips() {
        let ns = root().namespace_key("notes", 0);
        let sealed = ns
            .seal("item-1", b"the database decision was postgres")
            .unwrap();
        assert_eq!(
            ns.open("item-1", &sealed).unwrap(),
            b"the database decision was postgres"
        );
    }

    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        let ns = root().namespace_key("notes", 0);
        let sealed = ns.seal("item-1", b"postgres").unwrap();
        assert!(!sealed.ciphertext.windows(8).any(|w| w == b"postgres"));
    }

    /// The item id is bound as associated data on both layers, so a provider cannot answer
    /// "give me item X" with a relabelled item Y.
    #[test]
    fn an_item_cannot_be_relabelled_and_still_decrypt() {
        let ns = root().namespace_key("notes", 0);
        let sealed = ns.seal("item-1", b"secret").unwrap();
        assert!(matches!(
            ns.open("item-2", &sealed),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn a_different_namespace_cannot_open_it() {
        let r = root();
        let a = r.namespace_key("notes", 0);
        let b = r.namespace_key("other", 0);
        let sealed = a.seal("item-1", b"secret").unwrap();
        assert!(matches!(
            b.open("item-1", &sealed),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn a_different_root_cannot_open_it() {
        let a = RootKey::from_bytes([1u8; 32]).namespace_key("notes", 0);
        let b = RootKey::from_bytes([2u8; 32]).namespace_key("notes", 0);
        let sealed = a.seal("item-1", b"secret").unwrap();
        assert!(matches!(
            b.open("item-1", &sealed),
            Err(EnvelopeError::Decrypt)
        ));
    }

    /// Rotation is the revocation mechanism, and it must not require re-encrypting content.
    #[test]
    fn rotation_rewraps_the_key_and_leaves_the_ciphertext_alone() {
        let r = root();
        let g0 = r.namespace_key("notes", 0);
        let g1 = r.namespace_key("notes", 1);

        let sealed = g0.seal("item-1", b"secret").unwrap();
        let rotated = g0.rewrap(&g1, "item-1", &sealed).unwrap();

        assert_eq!(
            rotated.ciphertext, sealed.ciphertext,
            "content is NOT re-encrypted"
        );
        assert_eq!(rotated.nonce, sealed.nonce);
        assert_ne!(rotated.wrapped_key, sealed.wrapped_key, "the wrap changed");

        assert_eq!(g1.open("item-1", &rotated).unwrap(), b"secret");
        // The revoked generation can no longer read it — which is the whole point.
        assert!(matches!(
            g0.open("item-1", &rotated),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn every_item_gets_its_own_content_key() {
        let ns = root().namespace_key("notes", 0);
        let a = ns.seal("item-1", b"same plaintext").unwrap();
        let b = ns.seal("item-2", b"same plaintext").unwrap();
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "identical plaintexts must not produce identical ciphertexts"
        );
        assert_ne!(a.wrapped_key, b.wrapped_key);
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected_rather_than_returning_rubbish() {
        let ns = root().namespace_key("notes", 0);
        let mut sealed = ns.seal("item-1", b"secret").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(matches!(
            ns.open("item-1", &sealed),
            Err(EnvelopeError::Decrypt)
        ));
    }

    /// The handle must survive rotation, or revoking an agent orphans every stored item.
    #[test]
    fn the_namespace_handle_is_stable_across_key_rotations() {
        let r = root();
        assert_eq!(r.namespace_handle("notes"), r.namespace_handle("notes"));
        // Rotating the key changes the key...
        assert_ne!(
            r.namespace_key("notes", 0).as_bytes(),
            r.namespace_key("notes", 1).as_bytes()
        );
        // ...and deliberately does not change the handle.
        assert_eq!(r.namespace_handle("notes"), r.namespace_handle("notes"));
    }

    #[test]
    fn handles_differ_per_namespace_and_per_user() {
        let a = root();
        let b = RootKey::from_bytes([8u8; 32]);
        assert_ne!(a.namespace_handle("notes"), a.namespace_handle("other"));
        assert_ne!(a.namespace_handle("notes"), b.namespace_handle("notes"));
    }

    /// It is a keyed derivation, not a hash of the name: two users with a namespace called "notes"
    /// must not share a handle, or the provider can bucket users by what they call things.
    #[test]
    fn the_handle_does_not_leak_the_namespace_name() {
        let h = root().namespace_handle("medical-records");
        assert!(!h.to_hex().contains("6d65646963616c"));
    }

    #[test]
    fn generated_roots_differ() {
        let a = RootKey::generate().namespace_key("n", 0);
        let b = RootKey::generate().namespace_key("n", 0);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
