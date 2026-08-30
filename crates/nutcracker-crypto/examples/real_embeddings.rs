//! The blind index against embeddings from a real model, not synthetic vectors.
//!
//! `examples/leakage.rs` measures uniformly random vectors and `examples/geometry.rs` measures
//! synthetic anisotropy. Both are arguments about what *would* happen. This measures what does:
//! 48 sentences across 12 topics, embedded by `nomic-embed-text` (768-dim) on a real Ollama
//! install, with related pairs that share a topic and are deliberately **not** near-duplicates.
//!
//! Run: `cargo run -p nutcracker-crypto --example real_embeddings`.
//!
//! The corpus is committed beside this file so the number is reproducible without an Ollama box.

use nutcracker_crypto::{BlindIndex, IndexParams, RootKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct Item {
    topic: String,
    v: Vec<f32>,
}

#[derive(Deserialize)]
struct Corpus {
    model: String,
    dim: usize,
    items: Vec<Item>,
}

fn unit(mut v: Vec<f32>) -> Vec<f32> {
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-9);
    for x in &mut v {
        *x /= n;
    }
    v
}

fn cosine(a: &[f32], b: &[f32]) -> f64 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    f64::from(dot / (na * nb))
}

struct Score {
    recall: f64,
    false_rate: f64,
    unrelated_cos: f64,
}

/// Tokenise once per item, then compare tokens.
///
/// Not an optimisation, a correction: `shared_bands` re-derives every hyperplane component by
/// hashing `(plane, dimension)`, so calling it per *pair* is `pairs x planes x dims` hashes. At 48
/// items, 768 dimensions and 128 planes that is ~1.8 billion, and the first version of this file
/// ran for twenty minutes before I read what I had written. A client indexes an item once and
/// compares tokens thereafter, which is `items x planes x dims` and finishes instantly.
///
/// Worth recording as a property of the scheme rather than of this file: signature cost scales with
/// the embedding's dimensionality, so a 1536-dim model costs twice a 768-dim one to index, and any
/// implementation that recomputes per comparison is quadratic in the wrong thing.
fn score(idx: &BlindIndex, items: &[(String, Vec<f32>)]) -> Score {
    let toks: Vec<Vec<_>> = items.iter().map(|(_, v)| idx.tokens(v)).collect();
    let (mut rel, mut rel_hit, mut unrel, mut unrel_hit) = (0usize, 0usize, 0usize, 0usize);
    let mut cos_sum = 0f64;
    for i in 0..items.len() {
        for j in (i + 1)..items.len() {
            let shared = toks[i].iter().zip(&toks[j]).any(|(a, b)| a == b);
            if items[i].0 == items[j].0 {
                rel += 1;
                if shared {
                    rel_hit += 1;
                }
            } else {
                unrel += 1;
                cos_sum += cosine(&items[i].1, &items[j].1);
                if shared {
                    unrel_hit += 1;
                }
            }
        }
    }
    Score {
        recall: rel_hit as f64 / rel as f64 * 100.0,
        false_rate: unrel_hit as f64 / unrel as f64 * 100.0,
        unrelated_cos: cos_sum / unrel as f64,
    }
}

fn main() {
    let raw = include_str!("emb-nomic.json");
    let corpus: Corpus = serde_json::from_str(raw).expect("corpus must parse");

    let plain: Vec<(String, Vec<f32>)> = corpus
        .items
        .iter()
        .map(|i| (i.topic.clone(), unit(i.v.clone())))
        .collect();

    // Corpus mean, computed client-side as a client would.
    let mut mean = vec![0f32; corpus.dim];
    for (_, v) in &plain {
        for (m, x) in mean.iter_mut().zip(v) {
            *m += x;
        }
    }
    for m in &mut mean {
        *m /= plain.len() as f32;
    }
    let centred: Vec<(String, Vec<f32>)> = plain
        .iter()
        .map(|(t, v)| {
            (
                t.clone(),
                unit(v.iter().zip(&mean).map(|(x, m)| x - m).collect()),
            )
        })
        .collect();

    let ns = RootKey::from_bytes([3u8; 32]).namespace_key("notes", 0);
    println!(
        "{} , {} dims, {} sentences over {} topics",
        corpus.model,
        corpus.dim,
        plain.len(),
        plain
            .iter()
            .map(|(t, _)| t.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
    println!();
    println!(
        "{:>6} {:>6} {:>10} {:>10} {:>18} {:>12}",
        "bands", "bits", "recall", "false", "mean cos(unrel)", "corpus"
    );

    for (bands, bits) in [(8usize, 8usize), (16, 8), (8, 4), (16, 4)] {
        let idx = BlindIndex::new(
            &ns,
            IndexParams {
                bands,
                band_bits: bits,
            },
        );
        for (label, items) in [("as-is", &plain), ("centred", &centred)] {
            let s = score(&idx, items);
            println!(
                "{bands:>6} {bits:>6} {:>9.0}% {:>9.0}% {:>18.2} {:>12}",
                s.recall, s.false_rate, s.unrelated_cos, label
            );
        }
    }

    println!();
    println!("`recall` is a same-topic pair being retrieved; `false` is a different-topic pair");
    println!("coming back as a candidate, which is what the provider gets to observe.");
}
