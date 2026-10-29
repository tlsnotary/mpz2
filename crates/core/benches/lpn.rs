use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mpz_core::{lpn::LpnEncoder, prg::Prg};
use std::{hint::black_box, time::Duration};

/// Regular LPN parameter points `(n, k)` (t = 2000), spanning secret sizes from
/// L2-resident up to DRAM. Throughput is reported per output element
/// (correlation), so the effect of the `k`-block secret's cache residency on
/// the LPN encode is directly visible across the sweep.
const PARAMS: &[(usize, u32)] = &[
    (256_000, 16_384),
    (512_000, 32_768),
    (1_024_000, 65_536),
    (2_048_000, 131_072),
    (4_096_000, 262_144),
    (8_192_000, 262_144),
    (16_384_000, 524_288),
    (32_768_000, 1_048_576),
];

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("lpn");

    for &(n, k) in PARAMS {
        let seed = [0u8; 16];
        let lpn = LpnEncoder::<10>::new(k);
        let mut x = vec![[0u8; 16]; k as usize];
        let mut y = vec![[0u8; 16]; n];
        let mut prg = Prg::new();
        prg.random_bytes(x.as_flattened_mut());
        prg.random_bytes(y.as_flattened_mut());

        // Throughput = output correlations produced per second.
        group.throughput(Throughput::Elements(n as u64));

        // Label by the secret size (16 * k bytes), which determines cache
        // residency.
        let secret_kib = k as usize * 16 / 1024;
        group.bench_function(format!("secret={secret_kib}KiB/n={n}"), |bench| {
            bench.iter(|| {
                #[allow(clippy::unit_arg)]
                black_box(lpn.compute(seed, &mut y, &x));
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = lpn;
    config = Criterion::default().warm_up_time(Duration::from_millis(1000)).sample_size(10);
    targets = criterion_benchmark
}
criterion_main!(lpn);
