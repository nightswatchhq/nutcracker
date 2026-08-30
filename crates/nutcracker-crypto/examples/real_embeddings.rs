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

    // A sweep rather than four points, because the question is whether centring **moves the
    // recall/leakage frontier** or merely slides along it. Four points cannot answer that: two
    // configurations are only comparable when one beats the other on both axes at once.
    for (bands, bits) in [
        (4usize, 8usize),
        (8, 8),
        (12, 8),
        (16, 8),
        (24, 8),
        (32, 8),
        (4, 6),
        (8, 6),
        (16, 6),
        (32, 6),
        (4, 4),
        (8, 4),
        (16, 4),
        (32, 4),
    ] {
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
    println!("`recall` is a same-topic pair being retrieved. `false` is a different-topic pair");
    println!("coming back as a candidate, and it is **bandwidth, not disclosure** - the client");
    println!("decrypts and re-ranks, so an extra candidate costs a fetch and reveals nothing new.");
    println!("If anything a higher false rate HELPS query privacy: it is cover, because the");
    println!("provider cannot tell which candidate you actually wanted.");
    println!();
    println!("The per-item disclosure is `bits/item` = bands x bits, and it moves the other way.");

    // The comparison that decides whether centring is worth a migration. A configuration is
    // dominated when some other configuration beats it on recall AND on disclosure at once;
    // anything not dominated sits on the frontier. If centred points dominate as-is points, the
    // frontier moved and centring is a real improvement rather than another knob on the same
    // trade-off.
    let mut all: Vec<(String, usize, usize, f64, f64)> = Vec::new();
    for (bands, bits) in [
        (4usize, 8usize),
        (8, 8),
        (12, 8),
        (16, 8),
        (24, 8),
        (32, 8),
        (4, 6),
        (8, 6),
        (16, 6),
        (32, 6),
        (4, 4),
        (8, 4),
        (16, 4),
        (32, 4),
    ] {
        let idx = BlindIndex::new(
            &ns,
            IndexParams {
                bands,
                band_bits: bits,
            },
        );
        for (label, items) in [("as-is", &plain), ("centred", &centred)] {
            let s = score(&idx, items);
            all.push((label.to_string(), bands, bits, s.recall, s.false_rate));
        }
    }

    let dominates = |a: &(String, usize, usize, f64, f64), b: &(String, usize, usize, f64, f64)| {
        a.3 >= b.3 && a.4 <= b.4 && (a.3 > b.3 || a.4 < b.4)
    };

    println!();
    println!("Frontier (nothing measured beats these on both axes at once):");
    println!(
        "{:>10} {:>6} {:>6} {:>9} {:>9} {:>11}",
        "corpus", "bands", "bits", "recall", "false", "bits/item"
    );
    let mut frontier: Vec<_> = all
        .iter()
        .filter(|p| !all.iter().any(|q| dominates(q, p)))
        .collect();
    frontier.sort_by(|a, b| a.3.partial_cmp(&b.3).unwrap());
    for p in &frontier {
        println!(
            "{:>10} {:>6} {:>6} {:>8.0}% {:>8.0}% {:>11}",
            p.0,
            p.1,
            p.2,
            p.3,
            p.4,
            p.1 * p.2
        );
    }

    let centred_on_frontier = frontier.iter().filter(|p| p.0 == "centred").count();
    println!();
    println!(
        "{} of {} frontier points are centred.",
        centred_on_frontier,
        frontier.len()
    );
    let dominated_as_is = all
        .iter()
        .filter(|p| p.0 == "as-is" && all.iter().any(|q| q.0 == "centred" && dominates(q, p)))
        .count();
    println!(
        "{} as-is configurations are beaten outright by some centred one.",
        dominated_as_is
    );
}
