//! Isolated evaluator benchmarks.
//!
//! Records protocol messages for replay-based isolated benchmarking of
//! evaluator.
//!
//! Run with: cargo bench -p mpz-garble --bench evaluator

use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::executor::block_on;
use mpz_circuits::{AES128, Circuit};
use mpz_common::{
    Session,
    context::{
        RecordedMtData, recording_mt_context_with_limit, recording_st_context_with_limit,
        replay_mt_context_with_limit, replay_st_context,
    },
};
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_memory_core::{Array, binary::U8, correlated::Delta};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::{Call, prelude::*};
use rand::{SeedableRng, rngs::StdRng};

// Gate count thresholds
const THRESHOLDS: &[(u64, &str)] = &[(100_000, "100K"), (1_000_000, "1M"), (10_000_000, "10M")];

/// Calculate max frame length based on workload size.
fn max_frame_length(circuit: &Circuit, circuit_count: usize) -> usize {
    let bytes_per_gate = 32 + 16; // garbled gate + label overhead
    let overhead = 1.5; // serialization overhead
    let gates = circuit.and_count() * circuit_count;
    ((gates * bytes_per_gate) as f64 * overhead) as usize
}

/// Runs the full garble protocol with garbler and evaluator.
/// Records garbler->evaluator messages (ctx_gb is the recording context).
async fn run_protocol_record_garbler(
    ctx_gb: &mut mpz_common::Context,
    ctx_ev: &mut mpz_common::Context,
    circuit: Arc<Circuit>,
    circuit_count: usize,
    seed: u64,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let delta = Delta::random(&mut rng);

    let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

    let mut gb = Garbler::new(cot_send, [0u8; 16], delta);
    let mut ev = Evaluator::new(cot_recv);

    futures::join!(
        async {
            let key: Array<U8, 16> = gb.alloc().unwrap();
            gb.mark_private(key).unwrap();
            gb.assign(key, [0u8; 16]).unwrap();
            gb.commit(key).unwrap();

            for _ in 0..circuit_count {
                let msg: Array<U8, 16> = gb.alloc().unwrap();
                gb.mark_blind(msg).unwrap();
                gb.commit(msg).unwrap();

                let ciphertext: Array<U8, 16> = gb
                    .call(
                        Call::builder(circuit.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                std::mem::drop(gb.decode(ciphertext).unwrap());
            }

            gb.flush(ctx_gb).await.unwrap();
            gb.execute(ctx_gb).await.unwrap();
            gb.flush(ctx_gb).await.unwrap();
        },
        async {
            let key: Array<U8, 16> = ev.alloc().unwrap();
            ev.mark_blind(key).unwrap();
            ev.commit(key).unwrap();

            for _ in 0..circuit_count {
                let msg: Array<U8, 16> = ev.alloc().unwrap();
                ev.mark_private(msg).unwrap();
                ev.assign(msg, [42u8; 16]).unwrap();
                ev.commit(msg).unwrap();

                let ciphertext: Array<U8, 16> = ev
                    .call(
                        Call::builder(circuit.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                std::mem::drop(ev.decode(ciphertext).unwrap());
            }

            ev.flush(ctx_ev).await.unwrap();
            ev.execute(ctx_ev).await.unwrap();
            ev.flush(ctx_ev).await.unwrap();
        }
    );
}

/// Records garbler->evaluator messages for evaluator replay.
/// Returns recorded_bytes needed for deterministic replay.
fn record_for_evaluator(circuit: Arc<Circuit>, circuit_count: usize, seed: u64) -> Vec<u8> {
    block_on(async {
        // ctx_1 (garbler) is recorded, ctx_0 (evaluator) receives
        let (mut ctx_ev, mut ctx_gb, recorded) =
            recording_st_context_with_limit(1024 * 1024, max_frame_length(&circuit, circuit_count));

        run_protocol_record_garbler(&mut ctx_gb, &mut ctx_ev, circuit, circuit_count, seed).await;
        recorded.lock().unwrap().clone()
    })
}

/// Runs evaluator only with replay context.
async fn run_evaluator_with_replay(
    ctx: &mut mpz_common::Context,
    circuit: Arc<Circuit>,
    circuit_count: usize,
) {
    let (_, cot_recv) = ideal_cot([0u8; 16].into());
    let mut ev = Evaluator::new(cot_recv);

    let key: Array<U8, 16> = ev.alloc().unwrap();
    ev.mark_blind(key).unwrap();
    ev.commit(key).unwrap();

    for _ in 0..circuit_count {
        let msg: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_private(msg).unwrap();
        ev.assign(msg, [42u8; 16]).unwrap();
        ev.commit(msg).unwrap();

        let ciphertext: Array<U8, 16> = ev
            .call(
                Call::builder(circuit.clone())
                    .arg(key)
                    .arg(msg)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        std::mem::drop(ev.decode(ciphertext).unwrap());
    }

    ev.flush(ctx).await.unwrap();
    ev.execute(ctx).await.unwrap();
    ev.flush(ctx).await.unwrap();
}

// ============================================================================
// Multi-threaded isolated evaluator benchmark
// ============================================================================

/// Runs the full garble protocol with MT contexts.
/// Records garbler->evaluator messages.
async fn run_protocol_record_garbler_mt(
    exec_gb: &mut Session,
    exec_ev: &mut Session,
    circuit: Arc<Circuit>,
    circuit_count: usize,
    seed: u64,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let delta = Delta::random(&mut rng);

    let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

    let mut gb = Garbler::new(cot_send, [0u8; 16], delta);
    let mut ev = Evaluator::new(cot_recv);

    let mut ctx_gb = exec_gb.new_context().unwrap();
    let mut ctx_ev = exec_ev.new_context().unwrap();

    futures::join!(
        async {
            let key: Array<U8, 16> = gb.alloc().unwrap();
            gb.mark_private(key).unwrap();
            gb.assign(key, [0u8; 16]).unwrap();
            gb.commit(key).unwrap();

            for _ in 0..circuit_count {
                let msg: Array<U8, 16> = gb.alloc().unwrap();
                gb.mark_blind(msg).unwrap();
                gb.commit(msg).unwrap();

                let ciphertext: Array<U8, 16> = gb
                    .call(
                        Call::builder(circuit.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                std::mem::drop(gb.decode(ciphertext).unwrap());
            }

            gb.flush(&mut ctx_gb).await.unwrap();
            gb.execute(&mut ctx_gb).await.unwrap();
            gb.flush(&mut ctx_gb).await.unwrap();
        },
        async {
            let key: Array<U8, 16> = ev.alloc().unwrap();
            ev.mark_blind(key).unwrap();
            ev.commit(key).unwrap();

            for _ in 0..circuit_count {
                let msg: Array<U8, 16> = ev.alloc().unwrap();
                ev.mark_private(msg).unwrap();
                ev.assign(msg, [42u8; 16]).unwrap();
                ev.commit(msg).unwrap();

                let ciphertext: Array<U8, 16> = ev
                    .call(
                        Call::builder(circuit.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                std::mem::drop(ev.decode(ciphertext).unwrap());
            }

            ev.flush(&mut ctx_ev).await.unwrap();
            ev.execute(&mut ctx_ev).await.unwrap();
            ev.flush(&mut ctx_ev).await.unwrap();
        }
    );
}

/// Records garbler->evaluator messages for MT evaluator replay.
fn record_for_evaluator_mt(
    circuit: Arc<Circuit>,
    circuit_count: usize,
    seed: u64,
) -> RecordedMtData {
    block_on(async {
        // exec_1 (garbler) is recorded, exec_0 (evaluator) receives
        let (mut exec_ev, mut exec_gb, recorded) =
            recording_mt_context_with_limit(1024 * 1024, max_frame_length(&circuit, circuit_count));

        run_protocol_record_garbler_mt(&mut exec_gb, &mut exec_ev, circuit, circuit_count, seed)
            .await;
        recorded.lock().unwrap().clone()
    })
}

/// Runs MT evaluator only with replay context.
async fn run_evaluator_with_replay_mt(
    exec: &mut Session,
    circuit: Arc<Circuit>,
    circuit_count: usize,
) {
    let (_, cot_recv) = ideal_cot([0u8; 16].into());
    let mut ev = Evaluator::new(cot_recv);

    let mut ctx = exec.new_context().unwrap();

    let key: Array<U8, 16> = ev.alloc().unwrap();
    ev.mark_blind(key).unwrap();
    ev.commit(key).unwrap();

    for _ in 0..circuit_count {
        let msg: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_private(msg).unwrap();
        ev.assign(msg, [42u8; 16]).unwrap();
        ev.commit(msg).unwrap();

        let ciphertext: Array<U8, 16> = ev
            .call(
                Call::builder(circuit.clone())
                    .arg(key)
                    .arg(msg)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        std::mem::drop(ev.decode(ciphertext).unwrap());
    }

    ev.flush(&mut ctx).await.unwrap();
    ev.execute(&mut ctx).await.unwrap();
    ev.flush(&mut ctx).await.unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let circuit = AES128.clone();
    let gates_per_circuit = circuit.and_count() as u64;

    // ST isolated evaluator benchmark
    let mut group = c.benchmark_group("evaluator");
    group.sample_size(10);

    for &(threshold, name) in THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = circuit_count as u64 * gates_per_circuit;

        group.throughput(Throughput::Elements(actual_gates));

        let recorded = record_for_evaluator(circuit.clone(), circuit_count, 0);

        let circuit_clone = circuit.clone();
        group.bench_function(BenchmarkId::new("st", name), |b| {
            b.iter(|| {
                block_on(async {
                    let mut ctx = replay_st_context(
                        recorded.clone(),
                        max_frame_length(&circuit_clone, circuit_count),
                    );
                    run_evaluator_with_replay(&mut ctx, circuit_clone.clone(), circuit_count).await;
                })
            });
        });
    }

    group.finish();

    // MT isolated evaluator benchmark
    let mut group_mt = c.benchmark_group("evaluator");
    group_mt.sample_size(10);

    for &(threshold, name) in THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = circuit_count as u64 * gates_per_circuit;

        group_mt.throughput(Throughput::Elements(actual_gates));

        let recorded_mt = record_for_evaluator_mt(circuit.clone(), circuit_count, 0);

        let circuit_clone = circuit.clone();
        group_mt.bench_function(BenchmarkId::new("mt", name), |b| {
            b.iter(|| {
                block_on(async {
                    let mut exec = replay_mt_context_with_limit(
                        recorded_mt.clone(),
                        max_frame_length(&circuit_clone, circuit_count),
                    );
                    run_evaluator_with_replay_mt(&mut exec, circuit_clone.clone(), circuit_count)
                        .await;
                })
            });
        });
    }

    group_mt.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
