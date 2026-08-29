//! The four tools an agent actually sees, and the sealing that happens beneath them.

use nutcracker_crypto::{BlindIndex, IndexParams, NamespaceHandle, NamespaceKey, RootKey};
use nutcracker_store::IndexMode;
use serde::{Deserialize, Serialize};

use crate::transport::{ProviderTransport, SealedSearch, SealedWrite, TransportError};

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error(
        "this build has no embedder configured, so semantic search is unavailable; \
             memory.read still works"
    )]
    NoEmbedder,
}

/// A retrieved memory, decrypted locally.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Memory {
    pub item_id: String,
    pub text: String,
    /// How many index bands this shared with the query. The provider's contribution, and it is
    /// coarse: a bucket collision is a hint, not a similarity.
    pub shared_bands: usize,
    /// Cosine similarity between the query and this memory, computed **here**, after decryption.
    /// This is the ranking that matters, and the provider could not have computed it.
    pub score: f32,
}

/// Cosine similarity. Returns 0 for a zero-magnitude vector rather than NaN, because a NaN in a
/// sort comparator silently produces a nonsense ordering instead of an error.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

/// Turns text into an embedding. Runs locally; a remote embedder would ship the plaintext to a
/// third party and undo the entire design.
pub trait Embedder {
    fn embed(&self, text: &str) -> Vec<f32>;
}

/// The MCP tool schemas, as `tools/list` would return them.
///
/// They take **text**, not ciphertext, because the agent is talking to a local process that holds
/// the key. A provider-hosted server offering these same signatures would be asking for your
/// plaintext.
pub fn tool_definitions() -> serde_json::Value {
    serde_json::json!([
        {
            "name": "memory.write",
            "description": "Remember something. The text is encrypted on this machine before it leaves it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "What to remember."},
                    "namespace": {"type": "string", "description": "Which memory to write to.", "default": "default"},
                    "expires_at": {"type": "integer", "description": "Unix seconds. Omit to keep until forgotten."}
                },
                "required": ["text"]
            }
        },
        {
            "name": "memory.search",
            "description": "Recall things related to a query. Matching is narrowed by the provider over blinded buckets and ranked here.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "namespace": {"type": "string", "default": "default"},
                    "limit": {"type": "integer", "default": 10}
                },
                "required": ["query"]
            }
        },
        {
            "name": "memory.read",
            "description": "Fetch one memory by id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item_id": {"type": "string"},
                    "namespace": {"type": "string", "default": "default"}
                },
                "required": ["item_id"]
            }
        },
        {
            "name": "memory.forget",
            "description": "Delete a memory. The provider is asked to remove it and cannot prove that it did.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item_id": {"type": "string"},
                    "namespace": {"type": "string", "default": "default"}
                },
                "required": ["item_id"]
            }
        }
    ])
}

/// The shim itself. Holds the root key; everything leaving it is sealed.
pub struct MemoryTools<T: ProviderTransport, E: Embedder> {
    root: RootKey,
    generation: u32,
    params: IndexParams,
    transport: T,
    embedder: Option<E>,
}

impl<T: ProviderTransport, E: Embedder> MemoryTools<T, E> {
    pub fn new(root: RootKey, transport: T, embedder: Option<E>) -> Self {
        Self {
            root,
            generation: 0,
            params: IndexParams::default(),
            transport,
            embedder,
        }
    }

    pub fn with_params(mut self, params: IndexParams) -> Self {
        self.params = params;
        self
    }

    /// Bumps the namespace key generation. Existing items must be rewrapped and reindexed by the
    /// caller; this only changes what new writes use.
    pub fn rotate(&mut self) {
        self.generation += 1;
    }

    fn keys(&self, namespace: &str) -> (NamespaceKey, NamespaceHandle) {
        (
            self.root.namespace_key(namespace, self.generation),
            self.root.namespace_handle(namespace),
        )
    }

    pub fn write(
        &mut self,
        namespace: &str,
        item_id: &str,
        text: &str,
        expires_at: Option<u64>,
    ) -> Result<(), ToolError> {
        let (nsk, handle) = self.keys(namespace);
        let sealed = nsk
            .seal(item_id, text.as_bytes())
            .map_err(|e| ToolError::Crypto(e.to_string()))?;

        // No embedder means no index. The item is still stored and still readable by id — it is
        // simply not searchable, which is honest, rather than silently sending the text somewhere
        // to be embedded.
        let tokens = match &self.embedder {
            Some(e) => BlindIndex::new(&nsk, self.params).tokens(&e.embed(text)),
            None => Vec::new(),
        };

        self.transport.write(SealedWrite {
            namespace: handle,
            item_id: item_id.to_string(),
            sealed,
            tokens,
            mode: IndexMode::BlindIndex,
            expires_at,
        })?;
        Ok(())
    }

    pub fn read(&mut self, namespace: &str, item_id: &str) -> Result<Memory, ToolError> {
        let (nsk, handle) = self.keys(namespace);
        let sealed = self.transport.read(&handle, item_id)?;
        let plain = nsk
            .open(item_id, &sealed)
            .map_err(|e| ToolError::Crypto(e.to_string()))?;
        Ok(Memory {
            item_id: item_id.to_string(),
            text: String::from_utf8_lossy(&plain).into_owned(),
            shared_bands: 0,
            score: 1.0,
        })
    }

    /// Narrow at the provider by blinded buckets, then decrypt and rank here.
    pub fn search(
        &mut self,
        namespace: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<Memory>, ToolError> {
        let embedder = self.embedder.as_ref().ok_or(ToolError::NoEmbedder)?;
        let (nsk, handle) = self.keys(namespace);
        let tokens = BlindIndex::new(&nsk, self.params).tokens(&embedder.embed(query));

        let candidates = self.transport.search(SealedSearch {
            namespace: handle,
            tokens,
            // Over-fetch: the provider's ranking is coarse (shared bands only), so asking for
            // exactly `limit` would let its approximation decide the final answer.
            limit: limit.saturating_mul(4).max(limit),
        })?;

        // The fine ranking, which is the half the provider cannot do. Bucket collisions are a
        // coarse hint — at the default parameters roughly 3% of returned candidates are unrelated
        // — so handing the provider's ordering straight to the agent would surface those as
        // matches. Decrypt, re-embed, rank by actual similarity, then cut.
        let query_vec = embedder.embed(query);
        let mut out = Vec::new();
        for c in candidates {
            // A candidate that will not decrypt is not an error to surface to the agent — it is a
            // provider returning something from another key generation, or junk. Skip it.
            if let Ok(plain) = nsk.open(&c.item_id, &c.sealed) {
                let text = String::from_utf8_lossy(&plain).into_owned();
                out.push(Memory {
                    item_id: c.item_id,
                    score: cosine(&query_vec, &embedder.embed(&text)),
                    text,
                    shared_bands: c.shared_bands,
                });
            }
        }
        // Descending by score, ties broken on id so identical queries give identical orderings.
        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.item_id.cmp(&b.item_id))
        });
        out.truncate(limit);
        Ok(out)
    }

    pub fn forget(&mut self, namespace: &str, item_id: &str) -> Result<bool, ToolError> {
        let (_, handle) = self.keys(namespace);
        Ok(self.transport.forget(&handle, item_id)?)
    }
}
