//! What travels between the local shim and the provider.
//!
//! Every field here is opaque. The types are the contract: there is no variant of any of these
//! structs that can carry a plaintext or a key, so a bug cannot leak one — it can only fail to
//! compile.

use nutcracker_crypto::{BucketToken, NamespaceHandle, SealedItem};
use nutcracker_store::{Candidate, IndexMode};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("provider returned {status}: {body}")]
    Http { status: u16, body: String },
    #[error("payment required: {0}")]
    PaymentRequired(String),
    #[error("provider is unreachable: {0}")]
    Unreachable(String),
    #[error("item not found")]
    NotFound,
}

/// A sealed write. Note what is absent: no text, no embedding, no key.
#[derive(Debug, Clone, PartialEq)]
pub struct SealedWrite {
    pub namespace: NamespaceHandle,
    pub item_id: String,
    pub sealed: SealedItem,
    pub tokens: Vec<BucketToken>,
    pub mode: IndexMode,
    pub expires_at: Option<u64>,
}

/// A sealed search: bucket tokens only.
#[derive(Debug, Clone, PartialEq)]
pub struct SealedSearch {
    pub namespace: NamespaceHandle,
    pub tokens: Vec<BucketToken>,
    pub limit: usize,
}

/// The provider side, as the shim sees it. Implemented over HTTP in production and over an
/// in-process store in tests, which is how the round trip below can be exercised without a server.
pub trait ProviderTransport {
    fn write(&mut self, req: SealedWrite) -> Result<(), TransportError>;
    fn read(&mut self, ns: &NamespaceHandle, item_id: &str) -> Result<SealedItem, TransportError>;
    fn search(&mut self, req: SealedSearch) -> Result<Vec<Candidate>, TransportError>;
    fn forget(&mut self, ns: &NamespaceHandle, item_id: &str) -> Result<bool, TransportError>;
}
