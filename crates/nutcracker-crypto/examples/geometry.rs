//! What the recall numbers do **not** tell you.
//!
//! `examples/leakage.rs` measures the blind index against uniformly random vectors perturbed by
//! uniform noise. That is a fair characterisation of the LSH scheme in isolation and it is where
//! the published figures come from: 100% recall at 0.2, 94% at 0.5, ~3% false candidates.
//!
//! **Real sentence embeddings are not uniformly random vectors**, and the difference is not a
//! detail. They occupy a narrow cone rather than the whole sphere (the well-documented anisotropy
//! of transformer embeddings), and a real corpus clusters: notes about one project sit near each
//! other whether or not they are near-duplicates. Both properties push the same way — everything is
//! closer to everything else than uniform sampling suggests — and the quantity that suffers is the
//! false-candidate rate, which is the leakage side of the trade.
//!
//! So this measures the same index against corpora with the geometry a real one has. Run:
//! `cargo run -p nutcracker-crypto --example geometry`.
//!
//! The point is not that the original numbers are wrong. It is that they answer a question about
//! the scheme, and a reader will hear an answer about their notes.

use nutcracker_crypto::{BlindIndex, IndexParams, NamespaceKey, RootKey};
use rand::{rngs::StdRng, Rng, SeedableRng};

const D: usize = 64;
const TRIALS: usize = 400;

fn unit(mut v: Vec<f32>) -> Vec<f32> {
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-9);
    for x in &mut v {
        *x /= n;
    }
    v
}

fn random_unit(rng: &mut StdRng) -> Vec<f32> {
    unit((0..D).map(|_| rng.gen_range(-1.0f32..1.0)).collect())
}

/// A vector drawn near `centre`, mixing in `spread` of fresh randomness. Small spread means tightly
/// clustered, which is what a corpus about one subject looks like.
fn near(rng: &mut StdRng, centre: &[f32], spread: f32) -> Vec<f32> {
    let noise = random_unit(rng);
    unit(
        centre
            .iter()
            .zip(&noise)
            .map(|(c, n)| c * (1.0 - spread) + n * spread)
            .collect(),
    )
}

/// Squash every vector towards a shared axis, the way transformer embeddings crowd into a cone.
/// `strength` 0 leaves the sphere alone; 0.8 is severely anisotropic.
fn anisotropic(v: &[f32], axis: &[f32], strength: f32) -> Vec<f32> {
    unit(
        v.iter()
            .zip(axis)
            .map(|(x, a)| x * (1.0 - strength) + a * strength)
            .collect(),
    )
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

struct Row {
    label: &'static str,
    /// A related item is retrieved.
    recall: f64,
    /// An unrelated item is returned as a candidate. This is the leakage side.
    false_rate: f64,
    /// Mean cosine between unrelated items — the number that explains the other two.
    unrelated_cos: f64,
}

/// Subtract the corpus mean and re-normalise.
///
/// The standard remedy for anisotropy, and the reason it belongs here rather than in a paper: the
/// shared cone direction carries no information distinguishing one item from another, so hashing it
/// spends every hyperplane on a component every vector has in common. Removing it is what puts the
/// hyperplanes back to work.
///
/// It has a real operational cost. The mean must be computed client-side, where the plaintext is,
/// and it must be **stable for the lifetime of a namespace**: change it and every token computed
/// before disagrees with every token computed after, so the index silently stops matching its own
/// history. That is a migration, not a tuning knob.
fn centre(v: &[f32], mean: &[f32]) -> Vec<f32> {
    unit(v.iter().zip(mean).map(|(x, m)| x - m).collect())
}

fn measure(
    idx: &BlindIndex,
    rng: &mut StdRng,
    label: &'static str,
    aniso: f32,
    spread: f32,
) -> Row {
    measure_inner(idx, rng, label, aniso, spread, false)
}

/// The same corpus, centred before hashing.
fn measure_centred(
    idx: &BlindIndex,
    rng: &mut StdRng,
    label: &'static str,
    aniso: f32,
    spread: f32,
) -> Row {
    measure_inner(idx, rng, label, aniso, spread, true)
}

fn measure_inner(
    idx: &BlindIndex,
    rng: &mut StdRng,
    label: &'static str,
    aniso: f32,
    spread: f32,
    do_centre: bool,
) -> Row {
    let axis = random_unit(rng);
    let (mut hits, mut false_hits) = (0usize, 0usize);
    let mut cos_sum = 0f64;

    // A corpus mean estimated from a sample, as a client would: it does not get to see the true
    // distribution either.
    let mean: Vec<f32> = if do_centre {
        let mut acc = vec![0f32; D];
        const SAMPLE: usize = 500;
        for _ in 0..SAMPLE {
            let v = anisotropic(&random_unit(rng), &axis, aniso);
            for (a, x) in acc.iter_mut().zip(&v) {
                *a += x;
            }
        }
        acc.iter().map(|a| a / SAMPLE as f32).collect()
    } else {
        vec![0f32; D]
    };

    for _ in 0..TRIALS {
        // One cluster centre, a related item drawn near it, and an unrelated item from elsewhere.
        // The cone is applied ONCE, to each observed vector, and never to the latent cluster
        // structure underneath.
        //
        // An earlier version of this applied it twice — to the cluster centre as well — which
        // washed cluster identity into the shared direction, so centring removed both and recall
        // appeared to collapse to 13%. That was a property of the generator, not of the scheme, and
        // it would have published a wrong conclusion about the remedy. Anisotropy is a shared offset
        // sitting on top of the semantic signal; it is not the signal.
        let cluster = random_unit(rng);
        let base = anisotropic(&near(rng, &cluster, spread), &axis, aniso);
        let related = anisotropic(&near(rng, &cluster, spread), &axis, aniso);
        let unrelated = anisotropic(&random_unit(rng), &axis, aniso);

        let (base, related, unrelated) = if do_centre {
            (
                centre(&base, &mean),
                centre(&related, &mean),
                centre(&unrelated, &mean),
            )
        } else {
            (base, related, unrelated)
        };

        if idx.shared_bands(&base, &related) > 0 {
            hits += 1;
        }
        if idx.shared_bands(&base, &unrelated) > 0 {
            false_hits += 1;
        }
        cos_sum += cosine(&base, &unrelated) as f64;
    }

    Row {
        label,
        recall: hits as f64 / TRIALS as f64 * 100.0,
        false_rate: false_hits as f64 / TRIALS as f64 * 100.0,
        unrelated_cos: cos_sum / TRIALS as f64,
    }
}

fn main() {
    let ns: NamespaceKey = RootKey::from_bytes([3u8; 32]).namespace_key("notes", 0);
    let idx = BlindIndex::new(&ns, IndexParams::default());
    let mut rng = StdRng::seed_from_u64(7);

    println!("Blind index at the default 8 bands x 8 bits, against corpora of different shape.");
    println!();
    println!(
        "{:<34} {:>8} {:>14} {:>16}",
        "corpus", "recall", "false candidates", "mean cos(unrelated)"
    );

    let rows = [
        // The geometry the published numbers assume.
        measure(&idx, &mut rng, "uniform sphere, loose clusters", 0.0, 0.5),
        measure(&idx, &mut rng, "uniform sphere, tight clusters", 0.0, 0.2),
        // Transformer embeddings crowd into a cone. This is the part the original never modelled.
        measure(&idx, &mut rng, "mildly anisotropic (0.3)", 0.3, 0.5),
        measure(&idx, &mut rng, "anisotropic (0.6)", 0.6, 0.5),
        measure(&idx, &mut rng, "severely anisotropic (0.8)", 0.8, 0.5),
        measure(&idx, &mut rng, "anisotropic + tight clusters", 0.6, 0.2),
        // The remedy, on the same corpora that broke.
        measure_centred(&idx, &mut rng, "  ↳ 0.6 anisotropic, CENTRED", 0.6, 0.5),
        measure_centred(&idx, &mut rng, "  ↳ 0.8 anisotropic, CENTRED", 0.8, 0.5),
    ];

    for r in &rows {
        println!(
            "{:<34} {:>7.0}% {:>13.0}% {:>16.2}",
            r.label, r.recall, r.false_rate, r.unrelated_cos
        );
    }

    println!();
    println!("`false candidates` is the leakage side of the trade: an unrelated item whose bucket");
    println!("token matches, so the provider is asked for it and learns it was a candidate. It is");
    println!("not a correctness failure — the client decrypts and re-ranks — but it is bandwidth,");
    println!("and it is what the provider gets to observe.");
    println!();
    println!("Read the last column. As the corpus crowds into a cone, unrelated items stop being");
    println!(
        "orthogonal, and a scheme tuned on the uniform sphere is answering a question about a"
    );
    println!("geometry no real corpus has.");
}
