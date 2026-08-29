//! The provider's error paths. The happy path is covered end to end over real HTTP by
//! `nutcracker-agent --example http_roundtrip`; these are the cases that example cannot reach.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use nutcracker_provider::{router, AppState};
use tower::ServiceExt;

async fn call(state: AppState, req: Request<Body>) -> (StatusCode, String) {
    let res = router(state).oneshot(req).await.unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn post(path: &str, json: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(json.to_string()))
        .unwrap()
}

const NS: &str = "000102030405060708090a0b0c0d0e0f"; // 16 bytes
const SEALED: fn() -> serde_json::Value = || {
    serde_json::json!({
        "ciphertext": "00", "nonce": "00".repeat(24),
        "wrapped_key": "00", "wrap_nonce": "00".repeat(24)
    })
};

#[tokio::test]
async fn a_short_namespace_handle_is_rejected_not_padded() {
    let (status, body) = call(
        AppState::default(),
        post(
            "/v1/items",
            serde_json::json!({
                "namespace": "0001", "item_id": "a", "sealed": SEALED(), "tokens": []
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("16 hex bytes"));
}

#[tokio::test]
async fn a_malformed_token_is_rejected_rather_than_silently_dropped() {
    // A dropped token is a memory that quietly stops being findable, which is the worst
    // available failure: no error, no data loss, just worse recall forever.
    let (status, _) = call(
        AppState::default(),
        post(
            "/v1/items",
            serde_json::json!({
                "namespace": NS, "item_id": "a", "sealed": SEALED(), "tokens": ["zz"]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_malformed_nonce_is_rejected() {
    let (status, _) = call(
        AppState::default(),
        post("/v1/items", serde_json::json!({
            "namespace": NS, "item_id": "a",
            "sealed": {"ciphertext":"00","nonce":"0011","wrapped_key":"00","wrap_nonce":"00".repeat(24)},
            "tokens": []
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_well_formed_write_is_accepted() {
    let (status, _) = call(
        AppState::default(),
        post(
            "/v1/items",
            serde_json::json!({
                "namespace": NS, "item_id": "a", "sealed": SEALED(), "tokens": ["ff".repeat(16)]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

/// A limit is a resource bound, not a suggestion: one request must not be able to ask a provider
/// to serialise a whole namespace.
#[tokio::test]
async fn an_absurd_search_limit_is_clamped_rather_than_honoured() {
    let state = AppState::default();
    for i in 0..600 {
        let _ = call(
            state.clone(),
            post(
                "/v1/items",
                serde_json::json!({
                    "namespace": NS, "item_id": format!("i{i}"), "sealed": SEALED(),
                    "tokens": ["ff".repeat(16)]
                }),
            ),
        )
        .await;
    }
    let (status, body) = call(
        state,
        post(
            "/v1/search",
            serde_json::json!({
                "namespace": NS, "tokens": ["ff".repeat(16)], "limit": 100000
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let hits: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(hits.len(), 500, "clamped to the ceiling");
}

/// A 404 on delete would leak whether an item existed to anyone who guesses an id.
#[tokio::test]
async fn forgetting_something_that_was_never_there_does_not_leak_that_fact() {
    let (status, body) = call(
        AppState::default(),
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/items/{NS}/never-existed"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "not 404");
    assert!(
        body.contains("\"removed\":false"),
        "but it says plainly that nothing went"
    );
}

#[tokio::test]
async fn reading_an_unknown_item_is_a_404() {
    let (status, _) = call(
        AppState::default(),
        Request::builder()
            .uri(format!("/v1/items/{NS}/nope"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Anything that is not exactly "blind" is treated as the unsafe named mode. Defaulting the other
/// way would let a typo silently void a namespace's end-to-end claim.
#[tokio::test]
async fn an_unrecognised_index_mode_is_treated_as_unsafe_not_as_blind() {
    let state = AppState::default();
    let (status, _) = call(
        state.clone(),
        post(
            "/v1/items",
            serde_json::json!({
                "namespace": NS, "item_id": "a", "sealed": SEALED(),
                "tokens": [], "mode": "blindd"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    use nutcracker_crypto::NamespaceHandle;
    use nutcracker_store::MemoryStore;
    let mut h = [0u8; 16];
    for (i, b) in h.iter_mut().enumerate() {
        *b = i as u8;
    }
    assert!(
        !state.store.lock().unwrap().is_e2e(&NamespaceHandle(h)),
        "a typo in `mode` must fail closed"
    );
}

/// A provider that loses everything on restart is a demo. These pin the difference.
mod persistence {
    use super::*;
    use nutcracker_provider::AppState;

    fn tmpfile(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nutcracker-test-{name}-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[tokio::test]
    async fn an_item_survives_a_restart() {
        let path = tmpfile("survives");
        let state = AppState::with_data(path.clone()).unwrap();
        let (status, _) = call(
            state,
            post(
                "/v1/items",
                serde_json::json!({
                    "namespace": NS, "item_id": "a", "sealed": SEALED(), "tokens": ["ff".repeat(16)]
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // A second AppState over the same file is a restart.
        let reborn = AppState::with_data(path.clone()).unwrap();
        let (status, _) = call(
            reborn,
            Request::builder()
                .uri(format!("/v1/items/{NS}/a"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the item must still be there");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn a_forget_is_persisted_too_or_deleted_memories_come_back() {
        let path = tmpfile("forget");
        let state = AppState::with_data(path.clone()).unwrap();
        let _ = call(
            state.clone(),
            post(
                "/v1/items",
                serde_json::json!({
                    "namespace": NS, "item_id": "a", "sealed": SEALED(), "tokens": []
                }),
            ),
        )
        .await;
        let _ = call(
            state,
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/items/{NS}/a"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        let reborn = AppState::with_data(path.clone()).unwrap();
        let (status, _) = call(
            reborn,
            Request::builder()
                .uri(format!("/v1/items/{NS}/a"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a forgotten memory must not resurrect"
        );
        let _ = std::fs::remove_file(path);
    }

    /// The snapshot is ciphertext. If it ever is not, this is the test that should say so.
    #[tokio::test]
    async fn the_snapshot_on_disk_holds_no_plaintext() {
        use nutcracker_crypto::RootKey;
        let path = tmpfile("sealed");
        let state = AppState::with_data(path.clone()).unwrap();

        let nsk = RootKey::from_bytes([9u8; 32]).namespace_key("n", 0);
        let sealed = nsk.seal("a", b"a memorable secret phrase").unwrap();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

        let _ = call(
            state,
            post("/v1/items", serde_json::json!({
                "namespace": NS, "item_id": "a",
                "sealed": {
                    "ciphertext": hex(&sealed.ciphertext), "nonce": hex(&sealed.nonce),
                    "wrapped_key": hex(&sealed.wrapped_key), "wrap_nonce": hex(&sealed.wrap_nonce)
                },
                "tokens": []
            })),
        )
        .await;

        let raw = std::fs::read(&path).unwrap();
        for chunk in b"a memorable secret phrase".windows(6) {
            assert!(
                !raw.windows(chunk.len()).any(|w| w == chunk),
                "a fragment of the plaintext reached the snapshot file"
            );
        }
        let _ = std::fs::remove_file(path);
    }

    /// A corrupt snapshot must fail loudly. Starting empty would look identical to a provider
    /// that lost everything and did not mention it.
    #[tokio::test]
    async fn a_corrupt_snapshot_is_an_error_not_a_silent_fresh_start() {
        let path = tmpfile("corrupt");
        std::fs::write(&path, b"{ this is not json").unwrap();
        assert!(AppState::with_data(path.clone()).is_err());
        let _ = std::fs::remove_file(path);
    }
}
