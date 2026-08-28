//! Measures the recall/leakage tradeoff so the knob in `IndexParams` has numbers attached
//! rather than adjectives. Run: `cargo run -p nutcracker-crypto --example leakage`.

use nutcracker_crypto::{BlindIndex, IndexParams, RootKey};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn random_vec(rng: &mut StdRng, d: usize) -> Vec<f32> {
    (0..d).map(|_| rng.gen_range(-1.0..1.0)).collect()
}
fn perturb(rng: &mut StdRng, v: &[f32], s: f32) -> Vec<f32> {
    v.iter().map(|x| x + rng.gen_range(-s..s)).collect()
}

fn main() {
    let ns = RootKey::from_bytes([3u8; 32]).namespace_key("notes", 0);
    let mut rng = StdRng::seed_from_u64(1);
    const TRIALS: usize = 200;

    println!(
        "{:>6} {:>6} {:>8} {:>10} {:>10} {:>10}",
        "bands", "bits", "planes", "hit@near", "hit@far", "bits/item"
    );
    for (bands, bits) in [(4, 4), (8, 4), (8, 8), (16, 8), (8, 16), (16, 16)] {
        let p = IndexParams {
            bands,
            band_bits: bits,
        };
        let idx = BlindIndex::new(&ns, p);
        let (mut near_hits, mut far_hits) = (0usize, 0usize);
        for _ in 0..TRIALS {
            let base = random_vec(&mut rng, 64);
            let near = perturb(&mut rng, &base, 0.05);
            let far = random_vec(&mut rng, 64);
            if idx.shared_bands(&base, &near) > 0 {
                near_hits += 1;
            }
            if idx.shared_bands(&base, &far) > 0 {
                far_hits += 1;
            }
        }
        println!(
            "{bands:>6} {bits:>6} {:>8} {:>9.0}% {:>9.0}% {:>10}",
            p.hyperplanes(),
            near_hits as f64 / TRIALS as f64 * 100.0,
            far_hits as f64 / TRIALS as f64 * 100.0,
            bands * bits,
        );
    }
    println!();
    println!(
        "hit@near = a near-duplicate (0.05 perturbation) is retrieved. hit@far = an unrelated"
    );
    println!(
        "item is returned as a candidate — wasted bandwidth, not a correctness failure, since"
    );
    println!("the client decrypts and ranks. bits/item bounds what the provider learns per item.");

    // The honest part. 0.05 is a near-duplicate and recall there is easy. Semantic recall means
    // retrieving things that are *related*, not nearly identical, and that is where a bucketed
    // scheme earns or loses its keep.
    println!();
    println!("Recall against distance, at the default 8 bands x 8 bits:");
    println!("{:>12} {:>10}", "perturbation", "recall");
    let idx = BlindIndex::new(&ns, IndexParams::default());
    for scale in [0.05f32, 0.1, 0.2, 0.3, 0.5, 0.8, 1.2] {
        let mut hits = 0usize;
        for _ in 0..TRIALS {
            let base = random_vec(&mut rng, 64);
            let other = perturb(&mut rng, &base, scale);
            if idx.shared_bands(&base, &other) > 0 {
                hits += 1;
            }
        }
        println!(
            "{scale:>12.2} {:>9.0}%",
            hits as f64 / TRIALS as f64 * 100.0
        );
    }
    println!();
    println!("Read the bottom of that table, not the top. Near-duplicate recall is easy and not");
    println!("what anyone means by semantic search. Loosen the parameters to chase the tail and");
    println!("you disclose more; the tradeoff is real and this is the shape of it.");
}
