use criterion::{Criterion, criterion_group, criterion_main};
use mpz_core::{block::Block, ggm::GgmTree};
use std::hint::black_box;

#[allow(clippy::all)]
fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("ggm::gen::1K", move |bench| {
        let depth = 10;
        let seed = rand::random::<Block>();
        let mut leaves = vec![Block::ZERO; 1 << depth];
        bench.iter(|| {
            GgmTree::new_from_seed(depth, seed, &mut leaves);
            black_box(&leaves);
        });
    });

    c.bench_function("ggm::reconstruction::1K", move |bench| {
        let depth = 10;
        let sums = vec![Block::ZERO; depth];
        let mut leaves = vec![Block::ZERO; 1 << depth];
        bench.iter(|| {
            GgmTree::new_partial(depth, &sums, 420, &mut leaves);
            black_box(&leaves);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
