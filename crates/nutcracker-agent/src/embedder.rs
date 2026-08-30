//! A real local embedder, and the guard that stops swapping one from silently destroying an index.
//!
//! Until now the binary shipped `LocalBagOfBytes`, which is a histogram of byte values and not a
//! semantic model at all. It existed so the thing ran end to end with no dependency. This replaces
//! it with Ollama, which is local, and which the 2026-08-30 measurement in
//! `nutcracker-crypto/examples/real_embeddings.rs` used to produce the only honest retrieval
//! numbers this project has.
//!
//! ## Local is not a preference
//!
//! An embedder sees the plaintext. A remote one ships every memory to a third party in the clear
//! and undoes the entire design in one config line, which makes it the single easiest way to
//! destroy this product. So a non-loopback endpoint is **refused**, not warned about, and the
//! escape hatch is explicit and named after what it costs.
//!
//! ## Swapping an embedder is a migration, not a setting
//!
//! This is the part that would otherwise bite silently. Bucket tokens are derived from the
//! embedding, so two models produce two disjoint token spaces over the same memories. Change the
//! model and: everything stored before becomes unfindable, everything stored after looks fine, and
//! nothing errors. The user sees an assistant that has quietly forgotten one era of its life.
//!
//! The same hazard applies to the mean-centring fix the README describes, for the same reason, and
//! it is why that is described there as a migration rather than a knob.
//!
//! So the model identity is recorded beside the key on first use and checked on every start. A
//! mismatch refuses to run and says what changed. Refusing is the *point*: the alternative is
//! working perfectly and being wrong.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Why an embedding could not be produced. Every variant is a refusal, and none is a fallback:
/// returning a different vector space on failure is the silent-corruption path this module exists
/// to close.
#[derive(Debug, thiserror::Error)]
pub enum EmbedError {
    #[error("the embedder at {url} is not reachable: {source}. Is Ollama running?")]
    Unreachable {
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },
    #[error("the embedder returned no vector for this text")]
    Empty,
    #[error("the embedder answered but the response could not be read: {0}")]
    Malformed(String),
    #[error(
        "refusing a non-loopback embedder at {0}: an embedder sees plaintext, so a remote one \
         ships every memory to a third party in the clear. Pass \
         --i-accept-sending-plaintext-to-a-remote-embedder if that is genuinely what you want."
    )]
    NotLocal(String),
    #[error(
        "this namespace was indexed with `{recorded}` and you are running `{current}`. Bucket \
         tokens come from the embedding, so the two do not share a token space: everything stored \
         before would become unfindable and everything after would look fine, with no error. \
         Re-index deliberately, or put the old model back."
    )]
    ModelChanged { recorded: String, current: String },
    #[error(
        "this namespace was indexed at `{recorded}` bands x bits and you are running `{current}`. \
         A bucket token is that many hyperplane signs, so the two do not share a token space: the \
         same silent forgetting as changing the model. Re-index deliberately, or put the old \
         parameters back."
    )]
    ParamsChanged { recorded: String, current: String },
}

/// Text in, vector out. Fallible, deliberately: see the module docs.
pub trait Embedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError>;
    /// How this embedder identifies itself in the manifest. Two embedders that could produce
    /// different vectors for the same text must not share an id.
    fn id(&self) -> String;
}

/// So a `Box<dyn Embedder>` can be handed to `MemoryTools`, which is generic over one.
impl<T: Embedder + ?Sized> Embedder for Box<T> {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        (**self).embed(text)
    }
    fn id(&self) -> String {
        (**self).id()
    }
}

/// The placeholder, kept for tests and for running with nothing installed.
///
/// A histogram of byte values. It is deterministic and it is not a semantic model; two sentences
/// meaning the same thing in different words are not near each other. Keeping it is honest only
/// while it is named for what it is.
pub struct BagOfBytes;

impl Embedder for BagOfBytes {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        let mut v = vec![0f32; 64];
        for b in text.to_lowercase().bytes() {
            v[(b % 64) as usize] += 1.0;
        }
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1.0);
        Ok(v.iter().map(|x| x / norm).collect())
    }
    fn id(&self) -> String {
        "bag-of-bytes-v1".into()
    }
}

/// Ollama's embeddings endpoint, on this machine.
pub struct Ollama {
    url: String,
    model: String,
}

/// Loopback only, unless the caller has said in as many words that they accept the cost.
fn is_loopback(url: &str) -> bool {
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("")
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or_else(|| url.split("://").nth(1).unwrap_or(url));
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

impl Ollama {
    pub fn new(url: &str, model: &str, allow_remote: bool) -> Result<Self, EmbedError> {
        if !allow_remote && !is_loopback(url) {
            return Err(EmbedError::NotLocal(url.to_string()));
        }
        Ok(Self {
            url: url.trim_end_matches('/').to_string(),
            model: model.to_string(),
        })
    }
}

#[derive(Deserialize)]
struct OllamaResponse {
    #[serde(default)]
    embedding: Vec<f32>,
}

/// Subtract the model's shared direction and re-normalise.
///
/// Applied only when a reference mean exists for the model and the dimensions agree. A mean from
/// one model is meaningless for another, and silently applying a mismatched one would corrupt every
/// token while looking like it worked.
fn centre(v: Vec<f32>, mean: &[f32]) -> Vec<f32> {
    if v.len() != mean.len() {
        return v;
    }
    let mut out: Vec<f32> = v.iter().zip(mean).map(|(x, m)| x - m).collect();
    let n = out.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-9);
    for x in &mut out {
        *x /= n;
    }
    out
}

/// `:latest` is what Ollama reports for an untagged pull, and it is the same weights.
///
/// Normalised before the identity is built, not merely when looking up the mean. Without this the
/// same model pulled two ways gets two identities and the manifest refuses to start over a change
/// that never happened - a guard firing on its own noise, which is how a guard gets disabled.
fn canonical_model(model: &str) -> &str {
    model.strip_suffix(":latest").unwrap_or(model)
}

/// The reference mean for a model, when there is one.
fn reference_mean_for(model: &str) -> Option<&'static [f32]> {
    match canonical_model(model) {
        "nomic-embed-text" => Some(&crate::reference_mean::NOMIC_EMBED_TEXT_MEAN),
        _ => None,
    }
}

impl Embedder for Ollama {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        let body = serde_json::json!({ "model": self.model, "prompt": text });
        let mut res = ureq::post(format!("{}/api/embeddings", self.url))
            .send_json(&body)
            .map_err(|e| EmbedError::Unreachable {
                url: self.url.clone(),
                source: Box::new(e),
            })?;
        let mut s = String::new();
        res.body_mut()
            .as_reader()
            .read_to_string(&mut s)
            .map_err(|e| EmbedError::Malformed(e.to_string()))?;
        let parsed: OllamaResponse =
            serde_json::from_str(&s).map_err(|e| EmbedError::Malformed(e.to_string()))?;
        if parsed.embedding.is_empty() {
            return Err(EmbedError::Empty);
        }
        Ok(match reference_mean_for(&self.model) {
            Some(m) => centre(parsed.embedding, m),
            None => parsed.embedding,
        })
    }

    /// The identity carries whether centring was applied, and which version of the mean.
    ///
    /// It has to: a centred index and an uncentred one over the same model are disjoint token
    /// spaces, exactly as two different models are. Folding it into the id means the manifest check
    /// already written catches it, with no second mechanism to keep in step.
    fn id(&self) -> String {
        let m = canonical_model(&self.model);
        match reference_mean_for(m) {
            Some(_) => format!("ollama:{m}+centred-v1"),
            None => format!("ollama:{m}"),
        }
    }
}

/// What the index was built with. Written beside the key on first use.
///
/// The parameters are here as well as the embedder, and for the same reason: bucket tokens are
/// `bands x band_bits` hyperplane signs, so changing either number changes every token exactly as
/// changing the model does. Guarding one and not the other would leave the same trapdoor open with
/// a different label on it.
#[derive(Serialize, Deserialize, Debug)]
pub struct Manifest {
    pub embedder: String,
    /// `bands x band_bits`, e.g. `8x4`. Absent in manifests written before this was recorded, and
    /// treated as unknown rather than as a mismatch: refusing to start over a field that did not
    /// exist yet would break every existing install to guard against a change nobody made.
    #[serde(default)]
    pub params: Option<String>,
}

/// Record the embedder on first use, and refuse to run against a different one afterwards.
///
/// Deliberately a hard failure rather than a warning. A warning on stderr in an MCP server is a
/// warning nobody reads, and the damage it would be warning about is invisible: no error, no data
/// loss, just an assistant that has forgotten one era of its memories.
pub fn check_or_record(
    manifest_path: &Path,
    embedder: &dyn Embedder,
    params: &str,
) -> Result<(), EmbedError> {
    let current = embedder.id();
    if let Ok(raw) = std::fs::read_to_string(manifest_path) {
        if let Ok(m) = serde_json::from_str::<Manifest>(&raw) {
            if m.embedder != current {
                return Err(EmbedError::ModelChanged {
                    recorded: m.embedder,
                    current,
                });
            }
            if let Some(recorded) = m.params.as_deref() {
                if recorded != params {
                    return Err(EmbedError::ParamsChanged {
                        recorded: recorded.to_string(),
                        current: params.to_string(),
                    });
                }
            }
            return Ok(());
        }
    }
    // First use, or an unreadable manifest: record and continue. An unreadable one is treated as
    // absent rather than fatal, because refusing to start over a corrupt sidecar would be a worse
    // failure than the one being prevented.
    let _ = std::fs::write(
        manifest_path,
        serde_json::to_string_pretty(&Manifest {
            embedder: current,
            params: Some(params.to_string()),
        })
        .unwrap_or_default(),
    );
    Ok(())
}

/// `<key dir>/embedder.json`.
pub fn manifest_path_for(key: &Path) -> PathBuf {
    key.parent()
        .unwrap_or_else(|| Path::new("."))
        .join("embedder.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_recognised_and_anything_else_is_not() {
        for good in [
            "http://127.0.0.1:11434",
            "http://localhost:11434",
            "http://[::1]:11434",
            "http://127.0.0.1:11434/",
        ] {
            assert!(is_loopback(good), "{good} should be loopback");
        }
        for bad in [
            "https://api.openai.com",
            "http://192.168.0.13:11434",
            "http://embeddings.example.com:11434",
            // The one an attacker would try: a hostname that merely starts with the right text.
            "http://127.0.0.1.evil.com:11434",
            "http://localhost.evil.com",
        ] {
            assert!(!is_loopback(bad), "{bad} must not pass as loopback");
        }
    }

    /// The refusal tells the reader which flag to pass. It named a flag that did not exist, which
    /// is an instruction that fails when followed - worse than no instruction. Pinned so the two
    /// cannot drift apart again.
    #[test]
    fn the_refusal_names_the_flag_that_actually_exists() {
        let msg = EmbedError::NotLocal("https://x".into()).to_string();
        assert!(
            msg.contains("--i-accept-sending-plaintext-to-a-remote-embedder"),
            "message names a flag the CLI does not have: {msg}"
        );
    }

    #[test]
    fn a_remote_embedder_is_refused_rather_than_warned_about() {
        let e = match Ollama::new("https://api.example.com", "m", false) {
            Err(e) => e,
            Ok(_) => panic!("a remote embedder must be refused"),
        };
        assert!(matches!(e, EmbedError::NotLocal(_)));
        // And allowed only when the caller says so in as many words.
        assert!(Ollama::new("https://api.example.com", "m", true).is_ok());
    }

    #[test]
    fn the_bag_of_bytes_is_named_for_what_it_is() {
        assert_eq!(BagOfBytes.id(), "bag-of-bytes-v1");
        assert_eq!(BagOfBytes.embed("hello").unwrap().len(), 64);
    }

    #[test]
    fn two_models_do_not_share_an_id() {
        let a = Ollama::new("http://127.0.0.1:11434", "nomic-embed-text", false).unwrap();
        let b = Ollama::new("http://127.0.0.1:11434", "snowflake-arctic-embed2", false).unwrap();
        assert_ne!(a.id(), b.id());
        assert_ne!(a.id(), BagOfBytes.id());
    }

    /// The whole point of the manifest.
    #[test]
    fn changing_the_model_is_refused_with_an_explanation() {
        let dir = std::env::temp_dir().join(format!("nutcracker-mtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("embedder.json");
        let _ = std::fs::remove_file(&path);

        let first = Ollama::new("http://127.0.0.1:11434", "nomic-embed-text", false).unwrap();
        check_or_record(&path, &first, "8x4").expect("first use records");
        check_or_record(&path, &first, "8x4").expect("same model is fine");

        let other = Ollama::new("http://127.0.0.1:11434", "some-other-model", false).unwrap();
        let err = match check_or_record(&path, &other, "8x4") {
            Err(e) => e,
            Ok(()) => panic!("a changed model must be refused"),
        };
        match &err {
            EmbedError::ModelChanged { recorded, current } => {
                assert_eq!(recorded, "ollama:nomic-embed-text+centred-v1");
                assert_eq!(current, "ollama:some-other-model");
            }
            other => panic!("wrong error: {other}"),
        }
        // The message has to explain the damage, or nobody will understand why they are blocked.
        assert!(err.to_string().contains("unfindable"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_manifest_is_treated_as_absent_rather_than_fatal() {
        let dir = std::env::temp_dir().join(format!("nutcracker-ctest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("embedder.json");
        std::fs::write(&path, "not json").unwrap();
        check_or_record(&path, &BagOfBytes, "8x4")
            .expect("a corrupt sidecar must not block startup");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Centring must be visible in the identity, or an index built with it and one built without
    /// would silently share a manifest entry while having disjoint tokens.
    #[test]
    fn centring_is_part_of_the_identity() {
        let centred = Ollama::new("http://127.0.0.1:11434", "nomic-embed-text", false).unwrap();
        assert_eq!(centred.id(), "ollama:nomic-embed-text+centred-v1");

        // A model we have no mean for is left alone, and says so.
        let plain = Ollama::new("http://127.0.0.1:11434", "some-other-model", false).unwrap();
        assert_eq!(plain.id(), "ollama:some-other-model");
        assert_ne!(centred.id(), plain.id());
    }

    #[test]
    fn the_latest_tag_is_the_same_model() {
        let a = Ollama::new("http://127.0.0.1:11434", "nomic-embed-text", false).unwrap();
        let b = Ollama::new("http://127.0.0.1:11434", "nomic-embed-text:latest", false).unwrap();
        assert_eq!(
            a.id(),
            b.id(),
            "an untagged pull must not look like a different model"
        );
    }

    #[test]
    fn centring_removes_the_shared_direction_and_returns_a_unit_vector() {
        let mean = &crate::reference_mean::NOMIC_EMBED_TEXT_MEAN;
        // A vector that is nothing but the shared direction should collapse toward nothing, and
        // must still come back normalised rather than as NaNs.
        let out = centre(mean.to_vec(), mean);
        assert_eq!(out.len(), mean.len());
        assert!(out.iter().all(|x| x.is_finite()), "centring produced NaN");
        let norm = out.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-3 || norm < 1e-6, "norm was {norm}");
    }

    /// A mean from the wrong model is not applied. Silently subtracting a mismatched vector would
    /// corrupt every token while looking like it worked.
    #[test]
    fn a_mean_of_the_wrong_length_is_not_applied() {
        let v = vec![1.0f32, 2.0, 3.0];
        assert_eq!(centre(v.clone(), &[0.5f32, 0.5]), v);
    }

    #[test]
    fn the_reference_mean_is_the_models_dimensionality() {
        assert_eq!(crate::reference_mean::NOMIC_EMBED_TEXT_MEAN.len(), 768);
        let norm: f32 = crate::reference_mean::NOMIC_EMBED_TEXT_MEAN
            .iter()
            .map(|x| x * x)
            .sum::<f32>()
            .sqrt();
        // ~0.10 would mean no shared direction worth removing. 0.659 is the cone.
        assert!(
            norm > 0.5,
            "the reference mean has no cone in it: norm {norm}"
        );
    }

    /// The same trapdoor with a different label: tokens are `bands x bits` hyperplane signs, so
    /// changing the shape breaks them exactly as changing the model does.
    #[test]
    fn changing_the_parameters_is_refused_too() {
        let dir = std::env::temp_dir().join(format!("nutcracker-ptest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("embedder.json");
        let _ = std::fs::remove_file(&path);

        check_or_record(&path, &BagOfBytes, "8x4").expect("first use records");
        check_or_record(&path, &BagOfBytes, "8x4").expect("same params are fine");
        let err = match check_or_record(&path, &BagOfBytes, "8x8") {
            Err(e) => e,
            Ok(()) => panic!("changed parameters must be refused"),
        };
        assert!(matches!(err, EmbedError::ParamsChanged { .. }));
        assert!(err.to_string().contains("8x8"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A manifest written before parameters were recorded must not lock everyone out.
    #[test]
    fn an_older_manifest_without_params_is_accepted() {
        let dir = std::env::temp_dir().join(format!("nutcracker-otest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("embedder.json");
        std::fs::write(&path, r#"{"embedder":"bag-of-bytes-v1"}"#).unwrap();
        check_or_record(&path, &BagOfBytes, "8x4").expect("an older manifest must still start");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_manifest_sits_beside_the_key() {
        assert_eq!(
            manifest_path_for(Path::new("/home/x/.nutcracker/root.key")),
            PathBuf::from("/home/x/.nutcracker/embedder.json")
        );
    }
}
