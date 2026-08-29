//! The real transport: HTTP to a provider, sealed payloads only.

use nutcracker_crypto::{BucketToken, NamespaceHandle, SealedItem};
use nutcracker_store::{Candidate, IndexMode};

use crate::transport::{ProviderTransport, SealedSearch, SealedWrite, TransportError};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn sealed_json(s: &SealedItem) -> serde_json::Value {
    serde_json::json!({
        "ciphertext": hex(&s.ciphertext),
        "nonce": hex(&s.nonce),
        "wrapped_key": hex(&s.wrapped_key),
        "wrap_nonce": hex(&s.wrap_nonce),
    })
}

fn parse_sealed(v: &serde_json::Value) -> Option<SealedItem> {
    Some(SealedItem {
        ciphertext: unhex(v["ciphertext"].as_str()?)?,
        nonce: unhex(v["nonce"].as_str()?)?.try_into().ok()?,
        wrapped_key: unhex(v["wrapped_key"].as_str()?)?,
        wrap_nonce: unhex(v["wrap_nonce"].as_str()?)?.try_into().ok()?,
    })
}

/// Talks to a provider over HTTP. Every payload it sends is already sealed; it holds no keys and
/// could not encrypt anything if it wanted to, which is why it lives in its own module away from
/// the one that does.
pub struct HttpTransport {
    base: String,
    agent: ureq::Agent,
}

impl HttpTransport {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            agent: ureq::Agent::new_with_defaults(),
        }
    }

    fn err(e: ureq::Error) -> TransportError {
        match e {
            // 402 is the payment path a real provider fronts these handlers with. Surfacing it
            // distinctly matters: "you have not paid" and "the provider is down" want completely
            // different reactions from whoever is looking at the error.
            ureq::Error::StatusCode(402) => {
                TransportError::PaymentRequired("provider requires a TAP receipt".into())
            }
            ureq::Error::StatusCode(404) => TransportError::NotFound,
            ureq::Error::StatusCode(s) => TransportError::Http {
                status: s,
                body: String::new(),
            },
            other => TransportError::Unreachable(other.to_string()),
        }
    }
}

impl ProviderTransport for HttpTransport {
    fn write(&mut self, r: SealedWrite) -> Result<(), TransportError> {
        let body = serde_json::json!({
            "namespace": hex(&r.namespace.0),
            "item_id": r.item_id,
            "sealed": sealed_json(&r.sealed),
            "tokens": r.tokens.iter().map(|t| hex(&t.0)).collect::<Vec<_>>(),
            "mode": match r.mode { IndexMode::BlindIndex => "blind", IndexMode::PlaintextVectors => "plaintext_vectors" },
            "expires_at": r.expires_at,
        });
        self.agent
            .post(format!("{}/v1/items", self.base))
            .send_json(&body)
            .map_err(Self::err)?;
        Ok(())
    }

    fn read(&mut self, ns: &NamespaceHandle, item_id: &str) -> Result<SealedItem, TransportError> {
        let v: serde_json::Value = self
            .agent
            .get(format!("{}/v1/items/{}/{}", self.base, hex(&ns.0), item_id))
            .call()
            .map_err(Self::err)?
            .body_mut()
            .read_json()
            .map_err(|e| TransportError::Unreachable(e.to_string()))?;
        parse_sealed(&v).ok_or(TransportError::NotFound)
    }

    fn search(&mut self, r: SealedSearch) -> Result<Vec<Candidate>, TransportError> {
        let body = serde_json::json!({
            "namespace": hex(&r.namespace.0),
            "tokens": r.tokens.iter().map(|t| hex(&t.0)).collect::<Vec<_>>(),
            "limit": r.limit,
        });
        let v: serde_json::Value = self
            .agent
            .post(format!("{}/v1/search", self.base))
            .send_json(&body)
            .map_err(Self::err)?
            .body_mut()
            .read_json()
            .map_err(|e| TransportError::Unreachable(e.to_string()))?;

        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| {
                        Some(Candidate {
                            item_id: c["item_id"].as_str()?.to_string(),
                            sealed: parse_sealed(&c["sealed"])?,
                            shared_bands: c["shared_bands"].as_u64()? as usize,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn forget(&mut self, ns: &NamespaceHandle, item_id: &str) -> Result<bool, TransportError> {
        let v: serde_json::Value = self
            .agent
            .delete(format!("{}/v1/items/{}/{}", self.base, hex(&ns.0), item_id))
            .call()
            .map_err(Self::err)?
            .body_mut()
            .read_json()
            .map_err(|e| TransportError::Unreachable(e.to_string()))?;
        Ok(v["removed"].as_bool().unwrap_or(false))
    }
}

/// Bucket tokens are 16 bytes; anything else is a protocol error rather than something to coerce.
pub fn parse_token(s: &str) -> Option<BucketToken> {
    let b = unhex(s)?;
    (b.len() == 16).then(|| {
        let mut t = [0u8; 16];
        t.copy_from_slice(&b);
        BucketToken(t)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_junk() {
        assert_eq!(unhex(&hex(&[0, 1, 0xff])).unwrap(), vec![0, 1, 0xff]);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn a_sealed_item_survives_the_json_shape() {
        use nutcracker_crypto::RootKey;
        let ns = RootKey::from_bytes([3u8; 32]).namespace_key("n", 0);
        let s = ns.seal("i", b"hello").unwrap();
        assert_eq!(parse_sealed(&sealed_json(&s)).unwrap(), s);
    }

    #[test]
    fn a_truncated_nonce_fails_to_parse_rather_than_being_padded() {
        let v = serde_json::json!({
            "ciphertext": "00", "nonce": "0011", "wrapped_key": "00", "wrap_nonce": "00"
        });
        assert!(parse_sealed(&v).is_none());
    }
}
