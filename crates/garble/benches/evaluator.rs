//! Isolated evaluator benchmarks.
//!
//! The ST/MT protocol bodies live in `support/evaluator_body.rs`.
//!
//! Run with:
//!   cargo bench -p mpz-garble --features mock --bench evaluator         (ST only)
//!   cargo bench -p mpz-garble --features "mock rayon" --bench evaluator (MT only)

use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::executor::block_on;
use mpz_circuits::{AES128, Circuit};

#[allow(dead_code)] // The gated-out mode's body functions are unused.
#[path = "support/evaluator_body.rs"]
mod body;

use body::THRESHOLDS;

fn criterion_benchmark(c: &mut Criterion) {
    let circuit: Arc<Circuit> = AES128.clone();
    let gates_per_circuit = circuit.and_count() as u64;

    #[cfg(not(feature = "rayon"))]
    {
        // ST isolated evaluator benchmark
        let mut group = c.benchmark_group("evaluator");
        group.sample_size(10);

        for &(threshold, name) in THRESHOLDS {
            let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
            let actual_gates = circuit_count as u64 * gates_per_circuit;

            group.throughput(Throughput::Elements(actual_gates));

            let recorded = block_on(body::record_for_evaluator_st(
                circuit.clone(),
                circuit_count,
                0,
            ));

            let circuit_clone = circuit.clone();
            group.bench_function(BenchmarkId::new("st", name), |b| {
                b.iter_batched(
                    || {
                        body::replay_evaluator_st(
                            recorded.clone(),
                            circuit_clone.clone(),
                            circuit_count,
                        )
                    },
                    |mut ctx| {
                        block_on(body::run_evaluator_with_replay_st(
                            &mut ctx,
                            circuit_clone.clone(),
                            circuit_count,
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
        // MT isolated evaluator benchmark
        let mut group_mt = c.benchmark_group("evaluator");
        group_mt.sample_size(10);

        for &(threshold, name) in THRESHOLDS {
            let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
            let actual_gates = circuit_count as u64 * gates_per_circuit;

            group_mt.throughput(Throughput::Elements(actual_gates));

            let recorded_mt = block_on(body::record_for_evaluator_mt(
                circuit.clone(),
                circuit_count,
                0,
            ));

            let circuit_clone = circuit.clone();
            group_mt.bench_function(BenchmarkId::new("mt", name), |b| {
                b.iter_batched(
                    || {
                        body::replay_evaluator_mt(
                            recorded_mt.clone(),
                            circuit_clone.clone(),
                            circuit_count,
                        )
                    },
                    |mut exec| {
                        block_on(body::run_evaluator_with_replay_mt(
                            &mut exec,
                            circuit_clone.clone(),
                            circuit_count,
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
