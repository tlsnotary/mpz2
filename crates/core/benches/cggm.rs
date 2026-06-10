use criterion::{Criterion, black_box, criterion_group, criterion_main};
use mpz_core::cggm;

#[allow(clippy::all)]
fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("cggm::expand::1K", move |bench| {
        let depth = 10;
        let delta = rand::random::<[u8; 16]>();
        let seed = rand::random::<[u8; 16]>();
        let mut leaves = vec![[0u8; 16]; 1 << depth];
        let mut sums = vec![[0u8; 16]; depth];
        bench.iter(|| {
            cggm::expand(delta, seed, &mut leaves, &mut sums);
            black_box(&leaves);
        });
    });

    c.bench_function("cggm::expand_punctured::1K", move |bench| {
        let depth = 10;
        let sums = vec![[0u8; 16]; depth];
        let mut leaves = vec![[0u8; 16]; 1 << depth];
        bench.iter(|| {
            cggm::expand_punctured(420, &sums, &mut leaves);
            black_box(&leaves);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
