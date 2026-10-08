//! Evaluator benchmarks with message replay.
//!
//! Records garbler->evaluator messages once, then benchmarks
//! evaluator execution using replay contexts.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use mpz_circuits::AES128;
#[cfg(target_arch = "wasm32")]
use mpz_common::Session;
use mpz_common::context::{
    RecordedMtData, recording_mt_context_with_spawn_and_limit,
    replay_mt_context_with_spawn_and_limit,
};
#[cfg(target_arch = "wasm32")]
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
#[cfg(target_arch = "wasm32")]
use mpz_memory_core::{Array, binary::*, correlated::Delta};
#[cfg(target_arch = "wasm32")]
use mpz_ot::ideal::cot::ideal_cot;
#[cfg(target_arch = "wasm32")]
use mpz_vm_core::{Call, prelude::*};
#[cfg(target_arch = "wasm32")]
use rand::{SeedableRng, rngs::StdRng};

#[cfg(target_arch = "wasm32")]
use crate::BenchResult;

#[cfg(target_arch = "wasm32")]
async fn yield_to_browser() {
    use wasm_bindgen_futures::JsFuture;
    let promise = js_sys::Promise::resolve(&JsValue::NULL);
    let _ = JsFuture::from(promise).await;
}

#[cfg(target_arch = "wasm32")]
fn max_frame_length(circuit: &mpz_circuits::Circuit, circuit_count: usize) -> usize {
    let bytes_per_gate = 32;
    let overhead = 1.5;
    let and_gates = circuit.and_count() * circuit_count;
    ((and_gates * bytes_per_gate) as f64 * overhead) as usize
}

#[cfg(target_arch = "wasm32")]
async fn run_protocol_record_garbler(
    exec_gb: &mut Session,
    exec_ev: &mut Session,
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
                        Call::builder(AES128.clone())
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
                        Call::builder(AES128.clone())
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

#[cfg(target_arch = "wasm32")]
async fn record_for_evaluator(
    circuit_count: usize,
    seed: u64,
    concurrency: usize,
) -> RecordedMtData {
    // Record from evaluator's perspective (swap exec order)
    let (mut exec_ev, mut exec_gb, recorded) = recording_mt_context_with_spawn_and_limit(
        1024 * 1024,
        max_frame_length(&AES128, circuit_count),
        concurrency,
        |f| {
            let _ = web_spawn::spawn(f);
            Ok(())
        },
    );
    run_protocol_record_garbler(&mut exec_gb, &mut exec_ev, circuit_count, seed).await;
    recorded.lock().unwrap().clone()
}

#[cfg(target_arch = "wasm32")]
async fn run_evaluator_with_replay(exec: &mut Session, circuit_count: usize) {
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
                Call::builder(AES128.clone())
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

/// Benchmark evaluator with message replay.
///
/// # Arguments
/// * `n` - Number of benchmark iterations
/// * `batch_size` - Number of AND gates per iteration (circuit_count calculated
///   from this)
/// * `concurrency` - Maximum parallelism level
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn garble_evaluator(n: u32, batch_size: u32, concurrency: u32) -> BenchResult {
    let and_gates_per_circuit = AES128.and_count() as u64;
    let circuit_count = (batch_size as u64).div_ceil(and_gates_per_circuit) as usize;
    let actual_gates = circuit_count as u64 * and_gates_per_circuit;

    let performance = web_sys::window().unwrap().performance().unwrap();

    yield_to_browser().await;

    let recorded = record_for_evaluator(circuit_count, 0, concurrency as usize).await;
    yield_to_browser().await;

    let mut total_elapsed_ms = 0.0;

    for _ in 0..n {
        let start = performance.now();

        let mut exec = replay_mt_context_with_spawn_and_limit(
            recorded.clone(),
            max_frame_length(&AES128, circuit_count),
            concurrency as usize,
            |f| {
                let _ = web_spawn::spawn(f);
                Ok(())
            },
        );
        run_evaluator_with_replay(&mut exec, circuit_count).await;

        total_elapsed_ms += performance.now() - start;
    }

    BenchResult {
        elapsed_ms: total_elapsed_ms,
        and_gates: n as u64 * actual_gates,
    }
}
