//! The four tools an agent actually sees, and the sealing that happens beneath them.

use nutcracker_crypto::{BlindIndex, IndexParams, NamespaceHandle, NamespaceKey, RootKey};
use nutcracker_store::IndexMode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// The embedder refused or could not be reached.
    ///
    /// Surfaced rather than swallowed: an agent told "search failed, Ollama is not running" can
    /// act, where one silently handed results from a different vector space cannot. There is
    /// deliberately no fallback embedder here for the same reason.
    #[error(transparent)]
    Embed(#[from] crate::embedder::EmbedError),
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

/// Wraps the caller's item name and the text into one sealed payload.
///
/// Length-prefixed rather than JSON: the name is arbitrary user input and a delimiter would need
/// escaping, which is where this sort of thing usually goes wrong.
fn frame(item_id: &str, text: &str) -> Vec<u8> {
    let id = item_id.as_bytes();
    let mut out = Vec::with_capacity(4 + id.len() + text.len());
    out.extend_from_slice(&(id.len() as u32).to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(text.as_bytes());
    out
}

/// Inverse of [`frame`]. A payload that does not parse is treated as a bare pre-framing text with
/// an empty name rather than an error, so an older item stays readable instead of vanishing.
fn unframe(plain: &[u8]) -> (String, String) {
    if plain.len() >= 4 {
        let n = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
        if 4 + n <= plain.len() {
            return (
                String::from_utf8_lossy(&plain[4..4 + n]).into_owned(),
                String::from_utf8_lossy(&plain[4 + n..]).into_owned(),
            );
        }
    }
    (String::new(), String::from_utf8_lossy(plain).into_owned())
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

pub use crate::embedder::{EmbedError, Embedder};

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

    /// Blinds a caller-chosen item id before it reaches the provider.
    ///
    /// Found by running a provider on a second machine and reading its storage: the ciphertext was
    /// opaque, the bucket tokens were opaque, and sitting beside them in plain text was
    /// `item_id: "crossmachine"`. The shim's *default* ids are content hashes, so this only bites
    /// when a caller names one — and callers name things descriptively. `sofia-lease-renewal`
    /// would have told the provider everything the encryption was there to hide.
    ///
    /// Derived from the namespace *handle* rather than the namespace key, so it survives rotation.
    /// A rotating id would orphan every stored item the moment an agent was revoked.
    fn blind_id(&self, namespace: &str, item_id: &str) -> String {
        let mut h = Sha256::new();
        h.update(b"nutcracker:item:v1");
        h.update(self.root.namespace_handle(namespace).0);
        h.update(item_id.as_bytes());
        let d: [u8; 32] = h.finalize().into();
        d[..16].iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn write(
        &mut self,
        namespace: &str,
        item_id: &str,
        text: &str,
        expires_at: Option<u64>,
    ) -> Result<(), ToolError> {
        let (nsk, handle) = self.keys(namespace);
        let wire_id = self.blind_id(namespace, item_id);
        // The caller's own name for this memory goes INSIDE the ciphertext, not beside it. The
        // provider gets a blinded id it cannot reverse; the client recovers the real name on
        // decrypt, so `memory.search` can hand the agent back the name it chose rather than an
        // opaque hash it cannot then read or forget by.
        let sealed = nsk
            .seal(&wire_id, &frame(item_id, text))
            .map_err(|e| ToolError::Crypto(e.to_string()))?;

        // No embedder means no index. The item is still stored and still readable by id — it is
        // simply not searchable, which is honest, rather than silently sending the text somewhere
        // to be embedded.
        let tokens = match &self.embedder {
            Some(e) => BlindIndex::new(&nsk, self.params).tokens(&e.embed(text)?),
            None => Vec::new(),
        };

        self.transport.write(SealedWrite {
            namespace: handle,
            item_id: wire_id,
            sealed,
            tokens,
            mode: IndexMode::BlindIndex,
            expires_at,
        })?;
        Ok(())
    }

    pub fn read(&mut self, namespace: &str, item_id: &str) -> Result<Memory, ToolError> {
        let (nsk, handle) = self.keys(namespace);
        let wire_id = self.blind_id(namespace, item_id);
        let sealed = self.transport.read(&handle, &wire_id)?;
        let plain = nsk
            .open(&wire_id, &sealed)
            .map_err(|e| ToolError::Crypto(e.to_string()))?;
        let (_, text) = unframe(&plain);
        Ok(Memory {
            item_id: item_id.to_string(),
            text,
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
        let tokens = BlindIndex::new(&nsk, self.params).tokens(&embedder.embed(query)?);

        let candidates = self.transport.search(SealedSearch {
            namespace: handle,
            tokens,
            // Over-fetch: the provider's ranking is coarse (shared bands only), so asking for
            // exactly `limit` would let its approximation decide the final answer.
            limit: limit.saturating_mul(4).max(limit),
        })?;

        // The fine ranking, which is the half the provider cannot do. Bucket collisions are a
        // coarse hint, and a much coarser one than this comment used to claim: it said 3%, which
        // was measured on uniformly random vectors. Against real embeddings (nomic-embed-text,
        // 2026-08-30) the figure at the default parameters is **22%** of returned candidates being
        // unrelated. So handing the provider's ordering straight to the agent would surface roughly
        // one unrelated item in five as a match. Decrypt, re-embed, rank by actual similarity,
        // then cut.
        let query_vec = embedder.embed(query)?;
        let mut out = Vec::new();
        for c in candidates {
            // A candidate that will not decrypt is not an error to surface to the agent — it is a
            // provider returning something from another key generation, or junk. Skip it.
            if let Ok(plain) = nsk.open(&c.item_id, &c.sealed) {
                // The name the caller chose comes out of the ciphertext, so the agent gets back
                // an id it can actually pass to read or forget.
                let (name, text) = unframe(&plain);
                // A failure here is fatal to the search rather than skipped: dropping a candidate
                // because the embedder hiccuped would silently shorten the answer, and a shorter
                // answer that looks complete is the failure this whole module is careful about.
                let score = cosine(&query_vec, &embedder.embed(&text)?);
                out.push(Memory {
                    item_id: name,
                    score,
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
        let wire_id = self.blind_id(namespace, item_id);
        Ok(self.transport.forget(&handle, &wire_id)?)
    }
}
