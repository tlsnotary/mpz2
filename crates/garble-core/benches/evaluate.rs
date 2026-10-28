//! Benchmarks for half-gates evaluation.
//!
//! The scenarios live in `support/evaluate_body.rs` (shared verbatim with
//! `crates/wasm-bench` via `#[path]`).
//!
//! Run with: `cargo bench -p mpz-garble-core --bench evaluate`

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mpz_circuits::AES128;

#[path = "support/evaluate_body.rs"]
mod body;

use body::{EvaluateBench, EvaluateParallelBench, THRESHOLDS};

fn bench_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluate");
    group.sample_size(10);

    let gates_per_circuit = AES128.and_count() as u64;

    for &(threshold, name) in THRESHOLDS {
        let iterations = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = iterations as u64 * gates_per_circuit;

        group.throughput(Throughput::Elements(actual_gates));

        // Iterator-based (one gate at a time)
        let mut iter_bench = EvaluateBench::new(iterations);
        group.bench_function(BenchmarkId::new("iter", name), |b| {
            b.iter(|| iter_bench.run_iter());
        });

        // Batched (multiple gates at a time)
        let mut batched_bench = EvaluateBench::new(iterations);
        group.bench_function(BenchmarkId::new("batched", name), |b| {
            b.iter(|| batched_bench.run_batched());
        });
    }

    group.finish();
}

/// Bulk evaluation across many circuits (`evaluate_garbled_circuits`).
///
/// Not rayon-specific: without the `rayon` feature this measures the same
/// serial loop which `execute_preprocessed` uses in a non-rayon build.
fn bench_evaluate_bulk(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluate");
    group.sample_size(10);

    let gates_per_circuit = AES128.and_count() as u64;

    for &(threshold, name) in THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = circuit_count as u64 * gates_per_circuit;

        group.throughput(Throughput::Elements(actual_gates));

        let bench = EvaluateParallelBench::new(circuit_count);
        group.bench_function(BenchmarkId::new("bulk", name), |b| {
            b.iter_batched(
                || bench.circs(),
                body::evaluate,
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_evaluate, bench_evaluate_bulk);
criterion_main!(benches);
