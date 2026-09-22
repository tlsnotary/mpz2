//! Benchmarks for QuickSilver ZK verifier.
//!
//! Run with: cargo bench -p mpz-zk-core --bench verifier

use std::hint::black_box;

use blake3::Hasher;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mpz_circuits::AES128;
use mpz_memory_core::correlated::{Delta, Key, Mac};
use mpz_ot_core::{
    ideal::rcot::IdealRCOT,
    rcot::{RCOTReceiverOutput, RCOTSenderOutput},
};
use mpz_zk_core::{Prover, Verifier};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::sync::Arc;

// Gate count thresholds for execute
const THRESHOLDS: &[(u64, &str)] = &[(100_000, "100K"), (1_000_000, "1M"), (10_000_000, "10M")];

// Gate count thresholds for check
const CHECK_THRESHOLDS: &[(u64, &str)] = &[(200_000, "200K"), (400_000, "400K"), (600_000, "600K")];

/// Benchmarks only the execute phase (no check).
fn bench_verifier_execute(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier");
    group.sample_size(10);

    let circuit: Arc<mpz_circuits::Circuit> = AES128.clone();
    let and_count = circuit.and_count();
    let inputs_per_circuit = circuit.inputs().len();
    let gates_per_circuit = and_count as u64;

    for &(threshold, name) in THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = circuit_count as u64 * gates_per_circuit;

        group.throughput(Throughput::Elements(actual_gates));

        // Setup correlations
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let mut rcot = IdealRCOT::new(rng.random(), delta.into_inner());

        let total_inputs = inputs_per_circuit * circuit_count;
        rcot.alloc(total_inputs);
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput { mut keys, .. },
            RCOTReceiverOutput {
                msgs: mut macs,
                choices,
                ..
            },
        ) = rcot.transfer(total_inputs).unwrap();
        keys.iter_mut().for_each(|key| key.set_lsb(false));
        macs.iter_mut()
            .zip(&choices)
            .for_each(|(mac, &choice)| mac.set_lsb(choice));
        let input_keys = Key::from_blocks(keys);
        let input_macs = Mac::from_blocks(macs);

        let total_and_gates = and_count * circuit_count;
        rcot.alloc(total_and_gates);
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput { keys, .. },
            RCOTReceiverOutput {
                choices: gate_masks,
                msgs: macs,
                ..
            },
        ) = rcot.transfer(total_and_gates).unwrap();
        let gate_keys = Key::from_blocks(keys);
        let gate_macs = Mac::from_blocks(macs);

        // Pre-generate adjustments from prover
        let adjustments: Vec<Vec<bool>> = {
            let mut prover = Prover::default();
            let mut all_adjustments = Vec::with_capacity(circuit_count);

            for i in 0..circuit_count {
                let input_start = i * inputs_per_circuit;
                let input_end = input_start + inputs_per_circuit;
                let gate_start = i * and_count;
                let gate_end = gate_start + and_count;

                let mut prover_exec = prover
                    .execute(
                        circuit.clone(),
                        &input_macs[input_start..input_end],
                        &gate_masks[gate_start..gate_end],
                        &gate_macs[gate_start..gate_end],
                    )
                    .unwrap();

                let adj: Vec<bool> = prover_exec.iter().collect();
                let _ = prover_exec.finish().unwrap();
                all_adjustments.push(adj);
            }

            all_adjustments
        };

        let circuit_clone = circuit.clone();
        group.bench_function(BenchmarkId::new("execute", name), |b| {
            b.iter(|| {
                let mut verifier = Verifier::new(delta);

                for (i, adjustments_for_circuit) in
                    adjustments.iter().enumerate().take(circuit_count)
                {
                    let input_start = i * inputs_per_circuit;
                    let input_end = input_start + inputs_per_circuit;
                    let gate_start = i * and_count;
                    let gate_end = gate_start + and_count;

                    let mut verifier_exec = verifier
                        .execute(
                            circuit_clone.clone(),
                            &input_keys[input_start..input_end],
                            &gate_keys[gate_start..gate_end],
                        )
                        .unwrap();

                    let mut consumer = verifier_exec.consumer();
                    for &adjust in adjustments_for_circuit {
                        consumer.next(adjust);
                    }

                    let _ = verifier_exec.finish().unwrap();
                }

                black_box(())
            })
        });
    }

    group.finish();
}

/// Benchmarks only the check phase (execute in untimed setup).
fn bench_verifier_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier");
    group.sample_size(10);

    let circuit: Arc<mpz_circuits::Circuit> = AES128.clone();
    let and_count = circuit.and_count();
    let inputs_per_circuit = circuit.inputs().len();
    let gates_per_circuit = and_count as u64;

    for &(threshold, name) in CHECK_THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = circuit_count as u64 * gates_per_circuit;

        group.throughput(Throughput::Elements(actual_gates));

        // Setup correlations
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let mut rcot = IdealRCOT::new(rng.random(), delta.into_inner());

        let total_inputs = inputs_per_circuit * circuit_count;
        rcot.alloc(total_inputs);
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput { mut keys, .. },
            RCOTReceiverOutput {
                msgs: mut macs,
                choices,
                ..
            },
        ) = rcot.transfer(total_inputs).unwrap();
        keys.iter_mut().for_each(|key| key.set_lsb(false));
        macs.iter_mut()
            .zip(&choices)
            .for_each(|(mac, &choice)| mac.set_lsb(choice));
        let input_keys = Key::from_blocks(keys);
        let input_macs = Mac::from_blocks(macs);

        let total_and_gates = and_count * circuit_count;
        rcot.alloc(total_and_gates);
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput { keys, .. },
            RCOTReceiverOutput {
                choices: gate_masks,
                msgs: macs,
                ..
            },
        ) = rcot.transfer(total_and_gates).unwrap();
        let gate_keys = Key::from_blocks(keys);
        let gate_macs = Mac::from_blocks(macs);

        // SVOLE for check phase
        rcot.alloc(128);
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput {
                keys: svole_keys, ..
            },
            RCOTReceiverOutput {
                choices: svole_choices,
                msgs: svole_ev,
                ..
            },
        ) = rcot.transfer(128).unwrap();

        let circuit_clone = circuit.clone();
        group.bench_function(BenchmarkId::new("check", name), |b| {
            b.iter_batched(
                || {
                    // SETUP (not timed): build prover+verifier, run execute,
                    // run prover check
                    let mut prover = Prover::default();
                    let mut verifier = Verifier::new(delta);

                    for i in 0..circuit_count {
                        let input_start = i * inputs_per_circuit;
                        let input_end = input_start + inputs_per_circuit;
                        let gate_start = i * and_count;
                        let gate_end = gate_start + and_count;

                        let mut prover_exec = prover
                            .execute(
                                circuit_clone.clone(),
                                &input_macs[input_start..input_end],
                                &gate_masks[gate_start..gate_end],
                                &gate_macs[gate_start..gate_end],
                            )
                            .unwrap();
                        let mut verifier_exec = verifier
                            .execute(
                                circuit_clone.clone(),
                                &input_keys[input_start..input_end],
                                &gate_keys[gate_start..gate_end],
                            )
                            .unwrap();

                        let mut consumer = verifier_exec.consumer();
                        for adjust in prover_exec.iter() {
                            consumer.next(adjust);
                        }

                        let _ = prover_exec.finish().unwrap();
                        let _ = verifier_exec.finish().unwrap();
                    }

                    // Run prover check to get UV (not timed)
                    let mut prover_transcript = Hasher::default();
                    let uv = prover
                        .check(&mut prover_transcript, &svole_choices, &svole_ev)
                        .unwrap();

                    (verifier, Hasher::default(), uv)
                },
                |(mut verifier, mut verifier_transcript, uv)| {
                    // ROUTINE (timed): only verifier check
                    verifier
                        .check(&mut verifier_transcript, &svole_keys, uv)
                        .unwrap();
                },
                criterion::BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

criterion_group!(benches, bench_verifier_execute, bench_verifier_check);
criterion_main!(benches);
