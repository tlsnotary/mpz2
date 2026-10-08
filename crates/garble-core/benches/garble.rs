//! Benchmarks for half-gates garbling.
//!
//! Run with: `cargo bench -p mpz-garble-core --bench garble`

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mpz_circuits::AES128;
use mpz_garble_core::{Garbler, Key};
use mpz_memory_core::correlated::Delta;
use rand::{RngExt, SeedableRng, rngs::StdRng};

// Gate count thresholds
const THRESHOLDS: &[(u64, &str)] = &[(100_000, "100K"), (1_000_000, "1M"), (10_000_000, "10M")];

fn bench_garble(c: &mut Criterion) {
    let mut group = c.benchmark_group("garble");
    group.sample_size(10);
    let circuit = &*AES128;

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);
    let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();

    let gates_per_circuit = circuit.and_count() as u64;

    for &(threshold, name) in THRESHOLDS {
        let iterations = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = iterations as u64 * gates_per_circuit;

        group.throughput(Throughput::Elements(actual_gates));

        // Iterator-based (one gate at a time)
        group.bench_function(BenchmarkId::new("iter", name), |b| {
            let mut gb = Garbler::default();
            b.iter(|| {
                for _ in 0..iterations {
                    let mut iter = gb.generate(circuit, delta, &inputs).unwrap();
                    let _: Vec<_> = iter.by_ref().collect();
                    black_box(iter.finish().unwrap());
                }
            })
        });

        // Batched (multiple gates at a time)
        group.bench_function(BenchmarkId::new("batched", name), |b| {
            let mut gb = Garbler::default();
            b.iter(|| {
                for _ in 0..iterations {
                    let mut iter = gb.generate_batched(circuit, delta, &inputs).unwrap();
                    let _: Vec<_> = iter.by_ref().collect();
                    black_box(iter.finish().unwrap());
                }
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_garble);
criterion_main!(benches);
