//! Isolated verifier benchmarks.
//!
//! The ST/MT protocol bodies live in `support/verifier_body.rs` (shared
//! verbatim with `crates/wasm-bench` via `#[path]`).
//!
//! Run with:
//!   cargo bench -p mpz-zk --features mock --bench verifier           (ST only)
//!   cargo bench -p mpz-zk --features "mock rayon" --bench verifier   (MT only)

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::executor::block_on;
use mpz_circuits::AES128;

#[allow(dead_code)] // The gated-out mode's body functions are unused.
#[path = "support/verifier_body.rs"]
mod body;

use body::THRESHOLDS;

fn criterion_benchmark(c: &mut Criterion) {
    let circuit = &*AES128;
    let gates_per_circuit = circuit.and_count() as u64;

    #[cfg(not(feature = "rayon"))]
    {
        // ST verifier benchmark
        let mut group = c.benchmark_group("verifier");
        group.sample_size(10);

        for &(threshold, name) in THRESHOLDS {
            let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
            let actual_gates = circuit_count as u64 * gates_per_circuit;

            group.throughput(Throughput::Elements(actual_gates));

            let (recorded, ot_seed, delta) = block_on(body::record_for_verifier_st(circuit_count, 0));

            group.bench_function(BenchmarkId::new("st", name), |b| {
                b.iter_batched(
                    || body::replay_verifier_st(recorded.clone(), circuit_count),
                    |mut ctx| {
                        block_on(body::run_verifier_with_replay_st(
                            &mut ctx,
                            circuit_count,
                            delta,
                            ot_seed,
                        ))
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }

        group.finish();
    }

    #[cfg(feature = "rayon")]
    {
        // MT verifier benchmark
        let mut group_mt = c.benchmark_group("verifier");
        group_mt.sample_size(10);

        for &(threshold, name) in THRESHOLDS {
            let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
            let actual_gates = circuit_count as u64 * gates_per_circuit;

            group_mt.throughput(Throughput::Elements(actual_gates));

            let (recorded_mt, ot_seed, delta) =
                block_on(body::record_for_verifier_mt(circuit_count, 0));

            group_mt.bench_function(BenchmarkId::new("mt", name), |b| {
                b.iter_batched(
                    || body::replay_verifier_mt(recorded_mt.clone(), circuit_count),
                    |mut exec| {
                        block_on(body::run_verifier_with_replay_mt(
                            &mut exec,
                            circuit_count,
                            delta,
                            ot_seed,
                        ))
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }

        group_mt.finish();
    }
    }

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
