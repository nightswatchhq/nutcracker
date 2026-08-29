//! Proves the provider is real: seal locally, POST it, search it, decrypt what comes back.
//!
//! Start a provider first (`cargo run -p nutcracker-provider`), then
//! `cargo run -p nutcracker-agent --example http_roundtrip`.

use nutcracker_crypto::{BlindIndex, IndexParams, RootKey, SealedItem};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn post(base: &str, path: &str, b: &serde_json::Value) -> Vec<u8> {
    std::process::Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            &format!("{base}{path}"),
            "-H",
            "content-type: application/json",
            "-d",
            &b.to_string(),
        ])
        .output()
        .expect("curl")
        .stdout
}

fn main() {
    let base = std::env::var("PROVIDER").unwrap_or_else(|_| "http://127.0.0.1:8099".into());
    let root = RootKey::from_bytes([42u8; 32]);
    let nsk = root.namespace_key("demo", 0);
    let ns = hex(&root.namespace_handle("demo").0);
    let idx = BlindIndex::new(&nsk, IndexParams::default());

    let text = "the blind index keys its hyperplanes off the namespace secret";
    let sealed = nsk.seal("m1", text.as_bytes()).unwrap();
    let embedding: Vec<f32> = text.bytes().map(|b| (b % 32) as f32 / 32.0).collect();
    let tokens: Vec<String> = idx.tokens(&embedding).iter().map(|t| hex(&t.0)).collect();

    post(
        &base,
        "/v1/items",
        &serde_json::json!({
            "namespace": ns, "item_id": "m1",
            "sealed": {
                "ciphertext": hex(&sealed.ciphertext), "nonce": hex(&sealed.nonce),
                "wrapped_key": hex(&sealed.wrapped_key), "wrap_nonce": hex(&sealed.wrap_nonce)
            },
            "tokens": tokens,
        }),
    );
    println!("wrote m1 ({} bytes of ciphertext)", sealed.ciphertext.len());

    let out = post(
        &base,
        "/v1/search",
        &serde_json::json!({ "namespace": ns, "tokens": tokens, "limit": 5 }),
    );
    let hits: Vec<serde_json::Value> = serde_json::from_slice(&out).expect("search response");
    println!("search returned {} candidate(s)", hits.len());
    assert!(!hits.is_empty(), "the provider should have found it");

    let s = &hits[0]["sealed"];
    let recovered = nsk
        .open(
            hits[0]["item_id"].as_str().unwrap(),
            &SealedItem {
                ciphertext: unhex(s["ciphertext"].as_str().unwrap()),
                nonce: unhex(s["nonce"].as_str().unwrap()).try_into().unwrap(),
                wrapped_key: unhex(s["wrapped_key"].as_str().unwrap()),
                wrap_nonce: unhex(s["wrap_nonce"].as_str().unwrap()).try_into().unwrap(),
            },
        )
        .expect("decrypt");
    assert_eq!(recovered, text.as_bytes());
    println!("decrypted: {:?}", String::from_utf8_lossy(&recovered));
    println!(
        "\nThe provider stored, indexed and served that back without ever being able to read it."
    );
}
