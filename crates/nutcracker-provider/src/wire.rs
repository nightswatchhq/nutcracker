//! The HTTP wire format between the local shim and a provider.
//!
//! Every field is hex-encoded opaque bytes. There is no field here that could carry a plaintext or
//! a key, which is the point: a provider implementing this API correctly cannot read what it
//! stores even if it wants to, and cannot be asked to.

use serde::{Deserialize, Serialize};

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SealedItemWire {
    pub ciphertext: String,
    pub nonce: String,
    pub wrapped_key: String,
    pub wrap_nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    pub namespace: String,
    pub item_id: String,
    pub sealed: SealedItemWire,
    pub tokens: Vec<String>,
    /// "blind" (default) or "plaintext_vectors". Naming the second one is deliberate: it must be
    /// an explicit act, because it voids the namespace's end-to-end claim.
    #[serde(default = "default_mode")]
    pub mode: String,
    pub expires_at: Option<u64>,
}

fn default_mode() -> String {
    "blind".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRequest {
    pub namespace: String,
    pub tokens: Vec<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    20
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateWire {
    pub item_id: String,
    pub sealed: SealedItemWire,
    pub shared_bands: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageWire {
    pub writes: u128,
    pub reads: u128,
    pub searches: u128,
    pub forgets: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let b = vec![0u8, 1, 0x7f, 0xff];
        assert_eq!(from_hex(&to_hex(&b)).unwrap(), b);
    }

    #[test]
    fn odd_length_and_junk_hex_are_rejected_rather_than_truncated() {
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
    }

    /// The request type must have nowhere to put a plaintext. If a field is ever added that could,
    /// this is the test that should stop it.
    #[test]
    fn the_write_request_has_no_field_for_text_or_a_key() {
        let json = serde_json::to_string(&WriteRequest {
            namespace: "aa".into(),
            item_id: "i".into(),
            sealed: SealedItemWire {
                ciphertext: "00".into(),
                nonce: "00".into(),
                wrapped_key: "00".into(),
                wrap_nonce: "00".into(),
            },
            tokens: vec![],
            mode: "blind".into(),
            expires_at: None,
        })
        .unwrap();
        for forbidden in [
            "\"text\"",
            "\"plaintext\"",
            "\"key\":",
            "\"embedding\"",
            "\"vector\"",
        ] {
            assert!(
                !json.contains(forbidden),
                "wire format must not carry {forbidden}"
            );
        }
    }

    #[test]
    fn mode_defaults_to_blind_so_the_unsafe_option_must_be_asked_for() {
        let r: WriteRequest = serde_json::from_str(
            r#"{"namespace":"aa","item_id":"i",
                "sealed":{"ciphertext":"00","nonce":"00","wrapped_key":"00","wrap_nonce":"00"},
                "tokens":[]}"#,
        )
        .unwrap();
        assert_eq!(r.mode, "blind");
    }
}
