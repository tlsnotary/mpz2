use criterion::{Criterion, criterion_group, criterion_main};
use mpz_core::{Block, lpn::LpnEncoder, prg::Prg};
use std::{hint::black_box, time::Duration};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("lpn-rayon-small", move |bench| {
        let seed = Block::ZERO;
        let k = 5_060;
        let n = 166_400;
        let lpn = LpnEncoder::<10>::new(k);
        let mut x = vec![Block::ZERO; k as usize];
        let mut y = vec![Block::ZERO; n];
        let mut prg = Prg::new();
        prg.random_blocks(&mut x);
        prg.random_blocks(&mut y);
        bench.iter(|| {
            #[allow(clippy::unit_arg)]
            black_box(lpn.compute(seed, &mut y, &x));
        });
    });

    c.bench_function("lpn-rayon-medium", move |bench| {
        let seed = Block::ZERO;
        let k = 158_000;
        let n = 10_168_320;
        let lpn = LpnEncoder::<10>::new(k);
        let mut x = vec![Block::ZERO; k as usize];
        let mut y = vec![Block::ZERO; n];
        let mut prg = Prg::new();
        prg.random_blocks(&mut x);
        prg.random_blocks(&mut y);
        bench.iter(|| {
            #[allow(clippy::unit_arg)]
            black_box(lpn.compute(seed, &mut y, &x));
        });
    });

    c.bench_function("lpn-rayon-large", move |bench| {
        let seed = Block::ZERO;
        let k = 588_160;
        let n = 10_616_092;
        let lpn = LpnEncoder::<10>::new(k);
        let mut x = vec![Block::ZERO; k as usize];
        let mut y = vec![Block::ZERO; n];
        let mut prg = Prg::new();
        prg.random_blocks(&mut x);
        prg.random_blocks(&mut y);
        bench.iter(|| {
            #[allow(clippy::unit_arg)]
            black_box(lpn.compute(seed, &mut y, &x));
        });
    });
}

criterion_group! {
    name = lpn;
    config = Criterion::default().warm_up_time(Duration::from_millis(1000)).sample_size(10);
    targets = criterion_benchmark
}
criterion_main!(lpn);
