//! Isolated verifier benchmarks.
//!
//! Records protocol messages for replay-based isolated benchmarking of
//! verifier.
//!
//! Run with: cargo bench -p mpz-zk --bench verifier

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::executor::block_on;
use mpz_circuits::AES128;
use mpz_common::{
    Session,
    context::{
        RecordedMtData, recording_mt_context_with_limit, recording_st_context_with_limit,
        replay_mt_context_with_limit, replay_st_context,
    },
};
use mpz_core::Block;
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{
    Call,
    memory::{Array, binary::U8, correlated::Delta},
    prelude::*,
};
use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
use rand::{RngExt, SeedableRng, rngs::StdRng};

// Gate count thresholds
const THRESHOLDS: &[(u64, &str)] = &[(100_000, "100K"), (1_000_000, "1M"), (10_000_000, "10M")];

/// Calculate max frame length based on workload size.
fn max_frame_length(circuit: &mpz_circuits::Circuit, circuit_count: usize) -> usize {
    let bytes_per_correlation = 1 + 16; // choice bit + MAC
    let overhead = 1.2;
    let correlations = circuit.and_count() * circuit_count;
    ((correlations * bytes_per_correlation) as f64 * overhead) as usize
}

/// Runs the full ZK protocol with prover and verifier.
/// Records prover->verifier messages.
async fn run_protocol_record_prover(
    ctx_p: &mut mpz_common::Context,
    ctx_v: &mut mpz_common::Context,
    circuit_count: usize,
    seed: u64,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let delta = Delta::random(&mut rng);

    let (ot_send, ot_recv) = ideal_rcot(rng.random(), delta.into_inner());

    let prover_config = ProverConfig::builder().build().unwrap();
    let verifier_config = VerifierConfig::builder().build().unwrap();

    let mut prover = Prover::new(prover_config, ot_recv);
    let mut verifier = Verifier::new(verifier_config, delta, ot_send);

    futures::join!(
        async {
            let key: Array<U8, 16> = prover.alloc().unwrap();
            prover.mark_private(key).unwrap();
            prover.assign(key, [0u8; 16]).unwrap();
            prover.commit(key).unwrap();

            for _ in 0..circuit_count {
                let msg: Array<U8, 16> = prover.alloc().unwrap();
                prover.mark_public(msg).unwrap();
                prover.assign(msg, [42u8; 16]).unwrap();
                prover.commit(msg).unwrap();

                let ciphertext: Array<U8, 16> = prover
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                std::mem::drop(prover.decode(ciphertext).unwrap());
            }

            prover.flush(ctx_p).await.unwrap();
            prover.execute(ctx_p).await.unwrap();
            prover.flush(ctx_p).await.unwrap();
        },
        async {
            let key: Array<U8, 16> = verifier.alloc().unwrap();
            verifier.mark_blind(key).unwrap();
            verifier.commit(key).unwrap();

            for _ in 0..circuit_count {
                let msg: Array<U8, 16> = verifier.alloc().unwrap();
                verifier.mark_public(msg).unwrap();
                verifier.assign(msg, [42u8; 16]).unwrap();
                verifier.commit(msg).unwrap();

                let ciphertext: Array<U8, 16> = verifier
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                std::mem::drop(verifier.decode(ciphertext).unwrap());
            }

            verifier.flush(ctx_v).await.unwrap();
            verifier.execute(ctx_v).await.unwrap();
            verifier.flush(ctx_v).await.unwrap();
        }
    );
}

/// Records prover->verifier messages for verifier replay.
fn record_for_verifier(circuit_count: usize, seed: u64) -> (Vec<u8>, Block, Delta) {
    block_on(async {
        let (mut ctx_v, mut ctx_p, recorded) =
            recording_st_context_with_limit(1024 * 1024, max_frame_length(&AES128, circuit_count));

        let mut rng = StdRng::seed_from_u64(seed);
        let delta = Delta::random(&mut rng);
        let ot_seed: Block = rng.random();

        run_protocol_record_prover(&mut ctx_p, &mut ctx_v, circuit_count, seed).await;
        (recorded.lock().unwrap().clone(), ot_seed, delta)
    })
}

/// Runs verifier only with replay context.
async fn run_verifier_with_replay(
    ctx: &mut mpz_common::Context,
    circuit_count: usize,
    delta: Delta,
    ot_seed: Block,
) {
    let (ot_send, _) = ideal_rcot(ot_seed, delta.into_inner());
    let verifier_config = VerifierConfig::builder().build().unwrap();
    let mut verifier = Verifier::new(verifier_config, delta, ot_send);

    let key: Array<U8, 16> = verifier.alloc().unwrap();
    verifier.mark_blind(key).unwrap();
    verifier.commit(key).unwrap();

    for _ in 0..circuit_count {
        let msg: Array<U8, 16> = verifier.alloc().unwrap();
        verifier.mark_public(msg).unwrap();
        verifier.assign(msg, [42u8; 16]).unwrap();
        verifier.commit(msg).unwrap();

        let ciphertext: Array<U8, 16> = verifier
            .call(
                Call::builder(AES128.clone())
                    .arg(key)
                    .arg(msg)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        std::mem::drop(verifier.decode(ciphertext).unwrap());
    }

    verifier.flush(ctx).await.unwrap();
    verifier.execute(ctx).await.unwrap();
    verifier.flush(ctx).await.unwrap();
}

// ============================================================================
// Multi-threaded isolated verifier benchmark
// ============================================================================

/// Runs the full ZK protocol with MT contexts.
async fn run_protocol_record_prover_mt(
    exec_p: &mut Session,
    exec_v: &mut Session,
    circuit_count: usize,
    seed: u64,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let delta = Delta::random(&mut rng);

    let (ot_send, ot_recv) = ideal_rcot(rng.random(), delta.into_inner());

    let prover_config = ProverConfig::builder().build().unwrap();
    let verifier_config = VerifierConfig::builder().build().unwrap();

    let mut prover = Prover::new(prover_config, ot_recv);
    let mut verifier = Verifier::new(verifier_config, delta, ot_send);

    let mut ctx_p = exec_p.new_context().unwrap();
    let mut ctx_v = exec_v.new_context().unwrap();

    futures::join!(
        async {
            let key: Array<U8, 16> = prover.alloc().unwrap();
            prover.mark_private(key).unwrap();
            prover.assign(key, [0u8; 16]).unwrap();
            prover.commit(key).unwrap();

            for _ in 0..circuit_count {
                let msg: Array<U8, 16> = prover.alloc().unwrap();
                prover.mark_public(msg).unwrap();
                prover.assign(msg, [42u8; 16]).unwrap();
                prover.commit(msg).unwrap();

                let ciphertext: Array<U8, 16> = prover
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                std::mem::drop(prover.decode(ciphertext).unwrap());
            }

            prover.flush(&mut ctx_p).await.unwrap();
            prover.execute(&mut ctx_p).await.unwrap();
            prover.flush(&mut ctx_p).await.unwrap();
        },
        async {
            let key: Array<U8, 16> = verifier.alloc().unwrap();
            verifier.mark_blind(key).unwrap();
            verifier.commit(key).unwrap();

            for _ in 0..circuit_count {
                let msg: Array<U8, 16> = verifier.alloc().unwrap();
                verifier.mark_public(msg).unwrap();
                verifier.assign(msg, [42u8; 16]).unwrap();
                verifier.commit(msg).unwrap();

                let ciphertext: Array<U8, 16> = verifier
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                std::mem::drop(verifier.decode(ciphertext).unwrap());
            }

            verifier.flush(&mut ctx_v).await.unwrap();
            verifier.execute(&mut ctx_v).await.unwrap();
            verifier.flush(&mut ctx_v).await.unwrap();
        }
    );
}

/// Records prover->verifier messages for MT verifier replay.
fn record_for_verifier_mt(circuit_count: usize, seed: u64) -> (RecordedMtData, Block, Delta) {
    block_on(async {
        let (mut exec_v, mut exec_p, recorded) =
            recording_mt_context_with_limit(1024 * 1024, max_frame_length(&AES128, circuit_count));

        let mut rng = StdRng::seed_from_u64(seed);
        let delta = Delta::random(&mut rng);
        let ot_seed: Block = rng.random();

        run_protocol_record_prover_mt(&mut exec_p, &mut exec_v, circuit_count, seed).await;
        (recorded.lock().unwrap().clone(), ot_seed, delta)
    })
}

/// Runs MT verifier only with replay context.
async fn run_verifier_with_replay_mt(
    exec: &mut Session,
    circuit_count: usize,
    delta: Delta,
    ot_seed: Block,
) {
    let (ot_send, _) = ideal_rcot(ot_seed, delta.into_inner());
    let verifier_config = VerifierConfig::builder().build().unwrap();
    let mut verifier = Verifier::new(verifier_config, delta, ot_send);

    let mut ctx = exec.new_context().unwrap();

    let key: Array<U8, 16> = verifier.alloc().unwrap();
    verifier.mark_blind(key).unwrap();
    verifier.commit(key).unwrap();

    for _ in 0..circuit_count {
        let msg: Array<U8, 16> = verifier.alloc().unwrap();
        verifier.mark_public(msg).unwrap();
        verifier.assign(msg, [42u8; 16]).unwrap();
        verifier.commit(msg).unwrap();

        let ciphertext: Array<U8, 16> = verifier
            .call(
                Call::builder(AES128.clone())
                    .arg(key)
                    .arg(msg)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        std::mem::drop(verifier.decode(ciphertext).unwrap());
    }

    verifier.flush(&mut ctx).await.unwrap();
    verifier.execute(&mut ctx).await.unwrap();
    verifier.flush(&mut ctx).await.unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let circuit = &*AES128;
    let gates_per_circuit = circuit.and_count() as u64;

    // ST verifier benchmark
    let mut group = c.benchmark_group("verifier");
    group.sample_size(10);

    for &(threshold, name) in THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = circuit_count as u64 * gates_per_circuit;

        group.throughput(Throughput::Elements(actual_gates));

        let (recorded, ot_seed, delta) = record_for_verifier(circuit_count, 0);

        group.bench_function(BenchmarkId::new("st", name), |b| {
            b.iter(|| {
                block_on(async {
                    let mut ctx = replay_st_context(
                        recorded.clone(),
                        max_frame_length(circuit, circuit_count),
                    );
                    run_verifier_with_replay(&mut ctx, circuit_count, delta, ot_seed).await;
                })
            });
        });
    }

    group.finish();

    // MT verifier benchmark
    let mut group_mt = c.benchmark_group("verifier");
    group_mt.sample_size(10);

    for &(threshold, name) in THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = circuit_count as u64 * gates_per_circuit;

        group_mt.throughput(Throughput::Elements(actual_gates));

        let (recorded_mt, ot_seed, delta) = record_for_verifier_mt(circuit_count, 0);

        group_mt.bench_function(BenchmarkId::new("mt", name), |b| {
            b.iter(|| {
                block_on(async {
                    let mut exec = replay_mt_context_with_limit(
                        recorded_mt.clone(),
                        max_frame_length(circuit, circuit_count),
                    );
                    run_verifier_with_replay_mt(&mut exec, circuit_count, delta, ot_seed).await;
                })
            });
        });
    }

    group_mt.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
