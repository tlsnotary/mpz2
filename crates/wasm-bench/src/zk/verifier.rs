//! Isolated ZK verifier benchmark for WASM.
//!
//! Records protocol messages for replay-based isolated benchmarking.
//! This allows benchmarking verifier performance without network overhead.

use wasm_bindgen::prelude::*;

use std::sync::{Arc, Mutex};

use mpz_circuits::AES128;
#[cfg(target_arch = "wasm32")]
use mpz_common::Session;
use mpz_common::context::{
    RecordedMtData, recording_mt_context_with_spawn_and_limit,
    replay_mt_context_with_spawn_and_limit,
};
use mpz_core::Block;
use mpz_memory_core::{Array, binary::U8, correlated::Delta};
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{Call, prelude::*};
use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::BenchResult;

/// Calculate max frame length based on workload size.
fn max_frame_length(circuit: &mpz_circuits::Circuit, circuit_count: usize) -> usize {
    let bytes_per_correlation = 1 + 16; // choice bit + MAC
    let overhead = 1.2; // serialization overhead
    let correlations = circuit.and_count() * circuit_count;
    ((correlations * bytes_per_correlation) as f64 * overhead) as usize
}

/// Runs the full ZK protocol with MT contexts.
/// Records prover->verifier messages.
#[cfg(target_arch = "wasm32")]
async fn run_protocol_record_prover(
    exec_p: &mut Session,
    exec_v: &mut Session,
    seed: u64,
    circuit_count: usize,
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
        {
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

            async {
                prover.flush(&mut ctx_p).await.unwrap();
                prover.execute(&mut ctx_p).await.unwrap();
                prover.flush(&mut ctx_p).await.unwrap();
            }
        },
        {
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

            async {
                verifier.flush(&mut ctx_v).await.unwrap();
                verifier.execute(&mut ctx_v).await.unwrap();
                verifier.flush(&mut ctx_v).await.unwrap();
            }
        }
    );
}

/// Records prover->verifier messages for verifier replay.
#[cfg(target_arch = "wasm32")]
async fn record_for_verifier(
    seed: u64,
    circuit_count: usize,
    concurrency: usize,
) -> (RecordedMtData, Block, Delta) {
    // exec_1's writes are recorded, so prover uses exec_1
    let (mut exec_v, mut exec_p, recorded) = recording_mt_context_with_spawn_and_limit(
        1024 * 1024,
        max_frame_length(&AES128, circuit_count),
        concurrency,
        |f| {
            let _ = web_spawn::spawn(f);
            Ok(())
        },
    );

    // Capture delta and ot_seed for verifier replay
    let mut rng = StdRng::seed_from_u64(seed);
    let delta = Delta::random(&mut rng);
    let ot_seed: Block = rng.random();

    run_protocol_record_prover(&mut exec_p, &mut exec_v, seed, circuit_count).await;

    (recorded.lock().unwrap().clone(), ot_seed, delta)
}

/// Runs verifier only with replay context.
#[cfg(target_arch = "wasm32")]
async fn run_verifier_with_replay(
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

/// Benchmark isolated verifier with message replay.
///
/// Records prover->verifier messages once during setup,
/// then benchmarks verifier execution in isolation using replay.
///
/// # Arguments
/// * `n` - Number of iterations
/// * `gate_count` - Target number of AND gates (e.g., 100000, 1000000,
///   10000000)
/// * `concurrency` - Number of worker threads for parallel execution
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn zk_verifier(n: u32, gate_count: u32, concurrency: u32) -> BenchResult {
    use wasm_bindgen_futures::JsFuture;

    let and_gates_per_circuit = AES128.and_count();
    let circuit_count = (gate_count as usize).div_ceil(and_gates_per_circuit);
    let actual_gates = circuit_count * and_gates_per_circuit;

    let result: Arc<Mutex<Option<BenchResult>>> = Arc::new(Mutex::new(None));
    let result_clone = result.clone();

    // Run benchmark on web worker thread (where Atomics.wait is allowed)
    let _handle = web_spawn::spawn(move || {
        let bench_result = pollster::block_on(async {
            let global = js_sys::global();
            let performance: web_sys::Performance =
                js_sys::Reflect::get(&global, &"performance".into())
                    .expect("performance should exist")
                    .unchecked_into();

            // Record messages once (not timed)
            let (recorded, ot_seed, delta) =
                record_for_verifier(0, circuit_count, concurrency as usize).await;

            let mut total_elapsed_ms = 0.0;

            for _ in 0..n {
                // Timed section: verifier replay
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
                run_verifier_with_replay(&mut exec, circuit_count, delta, ot_seed).await;

                total_elapsed_ms += performance.now() - start;
            }

            BenchResult {
                elapsed_ms: total_elapsed_ms,
                and_gates: n as u64 * actual_gates as u64,
            }
        });
        *result_clone.lock().unwrap() = Some(bench_result);
    });

    // Poll for result on main thread
    loop {
        JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL))
            .await
            .unwrap();
        if let Some(r) = result.lock().unwrap().take() {
            return r;
        }
        let promise = js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 10)
                .unwrap();
        });
        JsFuture::from(promise).await.unwrap();
    }
}
