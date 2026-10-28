//! Isolated prover benchmarks.
//!
//! The ST/MT protocol bodies live in `support/prover_body.rs` (shared verbatim
//! with `crates/wasm-bench` via `#[path]`).
//!
//! Run with:
//!   cargo bench -p mpz-zk --features mock --bench prover           (ST only)
//!   cargo bench -p mpz-zk --features "mock rayon" --bench prover   (MT only)

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::executor::block_on;
use mpz_circuits::AES128;

#[allow(dead_code)] // The gated-out mode's body functions are unused.
#[path = "support/prover_body.rs"]
mod body;

use body::THRESHOLDS;

fn criterion_benchmark(c: &mut Criterion) {
    let circuit = &*AES128;
    let gates_per_circuit = circuit.and_count() as u64;

    #[cfg(not(feature = "rayon"))]
    {
        // ST prover benchmark
        let mut group = c.benchmark_group("prover");
        group.sample_size(10);

        for &(threshold, name) in THRESHOLDS {
            let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
            let actual_gates = circuit_count as u64 * gates_per_circuit;

            group.throughput(Throughput::Elements(actual_gates));

            let recorded = block_on(body::record_for_prover_st(circuit_count, 0));

            group.bench_function(BenchmarkId::new("st", name), |b| {
                b.iter_batched(
                    || body::replay_prover_st(recorded.clone(), circuit_count),
                    |mut ctx| block_on(body::run_prover_with_replay_st(&mut ctx, circuit_count)),
                    criterion::BatchSize::SmallInput,
                );
            });
        }

        group.finish();
    }

    #[cfg(feature = "rayon")]
    {
        // MT prover benchmark
        let mut group_mt = c.benchmark_group("prover");
        group_mt.sample_size(10);

        for &(threshold, name) in THRESHOLDS {
            let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
            let actual_gates = circuit_count as u64 * gates_per_circuit;

            group_mt.throughput(Throughput::Elements(actual_gates));

            let recorded_mt = block_on(body::record_for_prover_mt(circuit_count, 0));

            group_mt.bench_function(BenchmarkId::new("mt", name), |b| {
                b.iter_batched(
                    || body::replay_prover_mt(recorded_mt.clone(), circuit_count),
                    |mut exec| block_on(body::run_prover_with_replay_mt(&mut exec, circuit_count)),
                    criterion::BatchSize::SmallInput,
                );
            });
        }

        group_mt.finish();
    }
    }

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
