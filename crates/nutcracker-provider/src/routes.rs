//! The provider's HTTP surface.
//!
//! Four operations, matching the four metered ones in `MemoryDataService`. Payment is not wired
//! here: a real provider fronts this with the TAP receipt validation compass already implements,
//! and returns 402 without one. That belongs in front of these handlers rather than inside them,
//! and pretending otherwise would put a half-built payment path in a reference implementation.

use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use nutcracker_crypto::{BucketToken, NamespaceHandle, SealedItem};
use nutcracker_store::{InMemoryStore, IndexMode, MemoryStore, StoreError, StoredItem};

use crate::wire::*;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<InMemoryStore>>,
    /// Where to snapshot after each mutation. `None` keeps everything in memory, which is fine
    /// for a demo and useless for anything you would keep notes in.
    pub data_path: Option<Arc<std::path::PathBuf>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            store: Arc::new(Mutex::new(InMemoryStore::new())),
            data_path: None,
        }
    }
}

impl AppState {
    /// Loads a snapshot if one exists. A missing file is a fresh provider, not an error; a
    /// **corrupt** one is an error, because silently starting empty looks exactly like a provider
    /// that lost everything and decided not to mention it.
    pub fn with_data(path: std::path::PathBuf) -> anyhow::Result<Self> {
        let store = if path.exists() {
            let raw = std::fs::read(&path)?;
            let snap: nutcracker_store::Snapshot = serde_json::from_slice(&raw)?;
            InMemoryStore::restore(snap)
        } else {
            InMemoryStore::new()
        };
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            data_path: Some(Arc::new(path)),
        })
    }

    /// Writes via a temp file and renames, so an interrupted save cannot leave a half-written
    /// snapshot where a complete one used to be.
    fn persist(&self) {
        let Some(path) = &self.data_path else { return };
        let snap = self.store.lock().expect("store mutex").snapshot();
        let tmp = path.with_extension("tmp");
        let write = serde_json::to_vec(&snap)
            .map_err(|e| e.to_string())
            .and_then(|b| std::fs::write(&tmp, b).map_err(|e| e.to_string()))
            .and_then(|()| std::fs::rename(&tmp, path.as_path()).map_err(|e| e.to_string()));
        if let Err(e) = write {
            // Loudly. A provider that silently stops persisting looks perfectly healthy right up
            // until a restart, which is the exact failure mode this codebase keeps meeting.
            tracing::error!(
                error = %e, path = %path.display(),
                "FAILED TO PERSIST - data will be lost on restart"
            );
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/items", post(write))
        .route("/v1/items/{namespace}/{item_id}", get(read).delete(forget))
        .route("/v1/search", post(search))
        .route("/v1/usage", get(usage))
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
}

fn parse_handle(s: &str) -> Option<NamespaceHandle> {
    let b = from_hex(s)?;
    (b.len() == 16).then(|| {
        let mut h = [0u8; 16];
        h.copy_from_slice(&b);
        NamespaceHandle(h)
    })
}

fn parse_token(s: &str) -> Option<BucketToken> {
    let b = from_hex(s)?;
    (b.len() == 16).then(|| {
        let mut t = [0u8; 16];
        t.copy_from_slice(&b);
        BucketToken(t)
    })
}

fn parse_sealed(w: &SealedItemWire) -> Option<SealedItem> {
    let nonce: [u8; 24] = from_hex(&w.nonce)?.try_into().ok()?;
    let wrap_nonce: [u8; 24] = from_hex(&w.wrap_nonce)?.try_into().ok()?;
    Some(SealedItem {
        ciphertext: from_hex(&w.ciphertext)?,
        nonce,
        wrapped_key: from_hex(&w.wrapped_key)?,
        wrap_nonce,
    })
}

fn encode_sealed(s: &SealedItem) -> SealedItemWire {
    SealedItemWire {
        ciphertext: to_hex(&s.ciphertext),
        nonce: to_hex(&s.nonce),
        wrapped_key: to_hex(&s.wrapped_key),
        wrap_nonce: to_hex(&s.wrap_nonce),
    }
}

type ApiError = (StatusCode, String);

fn bad(msg: &str) -> ApiError {
    (StatusCode::BAD_REQUEST, msg.to_string())
}

async fn write(
    State(st): State<AppState>,
    Json(req): Json<WriteRequest>,
) -> Result<StatusCode, ApiError> {
    let ns = parse_handle(&req.namespace).ok_or_else(|| bad("namespace must be 16 hex bytes"))?;
    let sealed = parse_sealed(&req.sealed).ok_or_else(|| bad("malformed sealed item"))?;
    let tokens: Option<Vec<BucketToken>> = req.tokens.iter().map(|t| parse_token(t)).collect();
    let tokens = tokens.ok_or_else(|| bad("each token must be 16 hex bytes"))?;

    // Anything that is not exactly "blind" is treated as the named unsafe mode. Defaulting the
    // other way would let a typo silently void a namespace's end-to-end claim.
    let mode = if req.mode == "blind" {
        IndexMode::BlindIndex
    } else {
        IndexMode::PlaintextVectors
    };

    st.store
        .lock()
        .expect("store mutex")
        .put(
            &ns,
            StoredItem {
                item_id: req.item_id,
                sealed,
                tokens,
                mode,
                expires_at: req.expires_at,
            },
        )
        .map_err(|e| match e {
            StoreError::AtCapacity(n) => (
                StatusCode::INSUFFICIENT_STORAGE,
                format!("at capacity ({n})"),
            ),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    st.persist();
    Ok(StatusCode::CREATED)
}

async fn read(
    State(st): State<AppState>,
    Path((namespace, item_id)): Path<(String, String)>,
) -> Result<Json<SealedItemWire>, ApiError> {
    let ns = parse_handle(&namespace).ok_or_else(|| bad("namespace must be 16 hex bytes"))?;
    let sealed = st
        .store
        .lock()
        .expect("store mutex")
        .get(&ns, &item_id)
        .map_err(|_| (StatusCode::NOT_FOUND, "not found".to_string()))?;
    Ok(Json(encode_sealed(&sealed)))
}

async fn search(
    State(st): State<AppState>,
    Json(req): Json<SearchRequest>,
) -> Result<Json<Vec<CandidateWire>>, ApiError> {
    let ns = parse_handle(&req.namespace).ok_or_else(|| bad("namespace must be 16 hex bytes"))?;
    let tokens: Option<Vec<BucketToken>> = req.tokens.iter().map(|t| parse_token(t)).collect();
    let tokens = tokens.ok_or_else(|| bad("each token must be 16 hex bytes"))?;

    // A limit is a resource bound, not a suggestion. Without a ceiling one request can ask a
    // provider to serialise an entire namespace.
    let limit = req.limit.min(500);

    let hits = st
        .store
        .lock()
        .expect("store mutex")
        .search(&ns, &tokens, limit);
    Ok(Json(
        hits.into_iter()
            .map(|c| CandidateWire {
                item_id: c.item_id,
                sealed: encode_sealed(&c.sealed),
                shared_bands: c.shared_bands,
            })
            .collect(),
    ))
}

async fn forget(
    State(st): State<AppState>,
    Path((namespace, item_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ns = parse_handle(&namespace).ok_or_else(|| bad("namespace must be 16 hex bytes"))?;
    let removed = st.store.lock().expect("store mutex").forget(&ns, &item_id);
    st.persist();
    // 200 either way: the caller asked, the provider complied or had nothing to comply with, and
    // `removed` says which. A 404 here would leak whether an item existed to anyone who guesses.
    Ok(Json(serde_json::json!({ "removed": removed })))
}

async fn usage(State(st): State<AppState>) -> Json<UsageWire> {
    let u = st.store.lock().expect("store mutex").usage();
    Json(UsageWire {
        writes: u.writes,
        reads: u.reads,
        searches: u.searches,
        forgets: u.forgets,
    })
}
