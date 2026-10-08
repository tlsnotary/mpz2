//! Benchmarks for half-gates evaluation.
//!
//! Run with: `cargo bench -p mpz-garble-core --bench evaluate`

use std::{hint::black_box, sync::Arc};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mpz_circuits::{AES128, Circuit};
use mpz_garble_core::{Evaluator, GarbledCircuit, Garbler, Key, evaluate_garbled_circuits};
use mpz_memory_core::correlated::Delta;
use rand::{RngExt, SeedableRng, rngs::StdRng};

// Gate count thresholds
const THRESHOLDS: &[(u64, &str)] = &[(100_000, "100K"), (1_000_000, "1M"), (10_000_000, "10M")];

fn bench_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluate");
    group.sample_size(10);
    let circuit = &*AES128;

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);

    // Prepare inputs
    let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();
    let choices: Vec<bool> = (0..256).map(|_| rng.random()).collect();
    let eval_inputs: Vec<_> = inputs
        .iter()
        .zip(&choices)
        .map(|(k, &c)| k.auth(c, &delta))
        .collect();

    let gates_per_circuit = circuit.and_count() as u64;

    for &(threshold, name) in THRESHOLDS {
        let iterations = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = iterations as u64 * gates_per_circuit;

        // Pre-generate garbled circuits (single gates)
        let mut gb = Garbler::default();
        let all_gates: Vec<Vec<_>> = (0..iterations)
            .map(|_| {
                let mut iter = gb.generate(circuit, delta, &inputs).unwrap();
                let gates: Vec<_> = iter.by_ref().collect();
                let _ = iter.finish().unwrap();
                gates
            })
            .collect();

        group.throughput(Throughput::Elements(actual_gates));

        // Iterator-based (one gate at a time)
        group.bench_function(BenchmarkId::new("iter", name), |b| {
            let mut ev = Evaluator::default();
            b.iter(|| {
                for gates in &all_gates {
                    let mut consumer = ev.evaluate(circuit, &eval_inputs).unwrap();
                    for gate in gates {
                        consumer.next(*gate);
                    }
                    black_box(consumer.finish().unwrap());
                }
            })
        });

        // Batched (multiple gates at a time)
        // Note: EncryptedGateBatch doesn't implement Clone, so we regenerate
        // per iteration
        group.bench_function(BenchmarkId::new("batched", name), |b| {
            let mut ev = Evaluator::default();
            let mut gb = Garbler::default();
            b.iter(|| {
                for _ in 0..iterations {
                    // Regenerate batches (not timed separately, but included in
                    // measurement)
                    let mut iter = gb.generate_batched(circuit, delta, &inputs).unwrap();
                    let batches: Vec<_> = iter.by_ref().collect();
                    let _ = iter.finish().unwrap();

                    let mut consumer = ev.evaluate_batched(circuit, &eval_inputs).unwrap();
                    for batch in batches {
                        consumer.next(batch);
                    }
                    black_box(consumer.finish().unwrap());
                }
            })
        });
    }

    group.finish();
}

fn bench_evaluate_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluate_parallel");
    group.sample_size(10);
    let circuit: Arc<Circuit> = AES128.clone();

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);

    // Prepare inputs
    let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();
    let choices: Vec<bool> = (0..256).map(|_| rng.random()).collect();
    let eval_inputs: Vec<_> = inputs
        .iter()
        .zip(&choices)
        .map(|(k, &c)| k.auth(c, &delta))
        .collect();

    let gates_per_circuit = circuit.and_count() as u64;

    for &(threshold, name) in THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = circuit_count as u64 * gates_per_circuit;

        // Pre-garble circuits
        let mut gb = Garbler::default();
        let garbled_circuits: Vec<GarbledCircuit> = (0..circuit_count)
            .map(|_| {
                let mut iter = gb.generate(&circuit, delta, &inputs).unwrap();
                let gates: Vec<_> = iter.by_ref().collect();
                let _ = iter.finish().unwrap();
                GarbledCircuit { gates }
            })
            .collect();

        group.throughput(Throughput::Elements(actual_gates));

        // Parallel evaluation using evaluate_garbled_circuits (uses rayon
        // par_iter)
        group.bench_function(BenchmarkId::new("rayon", name), |b| {
            b.iter(|| {
                let circs: Vec<_> = garbled_circuits
                    .iter()
                    .map(|gc| (circuit.clone(), eval_inputs.clone(), gc.clone()))
                    .collect();
                black_box(evaluate_garbled_circuits(circs).unwrap())
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_evaluate, bench_evaluate_parallel);
criterion_main!(benches);
