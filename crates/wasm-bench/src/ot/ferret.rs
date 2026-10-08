//! Isolated Ferret OT benchmarks for WASM.
//!
//! Records protocol messages for replay-based isolated benchmarking of Ferret
//! sender. This allows benchmarking sender performance without network
//! overhead.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "wasm32")]
use mpz_common::Flush;
#[cfg(target_arch = "wasm32")]
use mpz_core::Block;
#[cfg(target_arch = "wasm32")]
use mpz_ot::ferret::{FerretConfig, Receiver, Sender};
#[cfg(target_arch = "wasm32")]
use mpz_ot::ideal::rcot::ideal_rcot;
#[cfg(target_arch = "wasm32")]
use mpz_ot_core::rcot::{RCOTReceiver, RCOTSender};
#[cfg(target_arch = "wasm32")]
use rand::{RngExt, SeedableRng, rngs::StdRng};

#[cfg(target_arch = "wasm32")]
use crate::BenchResult;

// ============================================================================
// Benchmark parameters
// ============================================================================

/// Calculate max frame length based on workload size.
#[cfg(target_arch = "wasm32")]
fn max_frame_length() -> usize {
    // Ferret messages include SPCOT data which can be large
    // Use large buffer for production parameters
    64 * 1024 * 1024 // 64 MB
}

/// Creates the Ferret config for benchmarking.
#[cfg(target_arch = "wasm32")]
fn bench_config() -> FerretConfig {
    FerretConfig::default()
}

// ============================================================================
// MT isolated sender benchmark
// ============================================================================

#[cfg(target_arch = "wasm32")]
use mpz_common::Session;
use mpz_common::context::{
    RecordedMtData, recording_mt_context_with_spawn_and_limit,
    replay_mt_context_with_spawn_and_limit,
};

/// Recorded data needed for deterministic MT replay.
#[cfg(target_arch = "wasm32")]
struct RecordedDataMt {
    /// Recorded bytes from receiver -> sender (per channel).
    data: RecordedMtData,
    /// Delta correlation.
    delta: Block,
    /// Seed for IdealRCOTSender.
    cot_seed: Block,
    /// Seed for Ferret sender.
    sender_seed: Block,
}

/// Runs the full Ferret protocol with MT contexts.
/// Records receiver->sender messages.
#[cfg(target_arch = "wasm32")]
#[allow(clippy::too_many_arguments)]
async fn run_protocol_record_receiver_mt(
    exec_sender: &mut Session,
    exec_receiver: &mut Session,
    config: FerretConfig,
    delta: Block,
    cot_seed: Block,
    sender_seed: Block,
    receiver_seed: Block,
    ot_count: usize,
) {
    let (cot_send, cot_recv) = ideal_rcot(cot_seed, delta);

    let mut sender = Sender::new(config.clone(), sender_seed, cot_send);
    let mut receiver = Receiver::new(config, receiver_seed, cot_recv);

    let mut ctx_sender = exec_sender.new_context().unwrap();
    let mut ctx_receiver = exec_receiver.new_context().unwrap();

    futures::join!(
        async {
            sender.alloc(ot_count).unwrap();
            let output = sender.queue_send_rcot(ot_count).unwrap();
            sender.flush(&mut ctx_sender).await.unwrap();
            let _ = output.await.unwrap();
        },
        async {
            receiver.alloc(ot_count).unwrap();
            let output = receiver.queue_recv_rcot(ot_count).unwrap();
            receiver.flush(&mut ctx_receiver).await.unwrap();
            let _ = output.await.unwrap();
        }
    );
}

/// Records receiver->sender messages for MT sender replay.
#[cfg(target_arch = "wasm32")]
async fn record_for_sender_mt(seed: u64, concurrency: usize, ot_count: usize) -> RecordedDataMt {
    let mut rng = StdRng::seed_from_u64(seed);
    let delta: Block = rng.random();
    let cot_seed: Block = rng.random();
    let sender_seed: Block = rng.random();
    let receiver_seed: Block = rng.random();

    // exec_1 (receiver) is recorded, exec_0 (sender) receives
    let (mut exec_sender, mut exec_receiver, recorded) = recording_mt_context_with_spawn_and_limit(
        1024 * 1024,
        max_frame_length(),
        concurrency,
        |f| {
            let _ = web_spawn::spawn(f);
            Ok(())
        },
    );

    let config = bench_config();

    run_protocol_record_receiver_mt(
        &mut exec_sender,
        &mut exec_receiver,
        config,
        delta,
        cot_seed,
        sender_seed,
        receiver_seed,
        ot_count,
    )
    .await;

    RecordedDataMt {
        data: recorded.lock().unwrap().clone(),
        delta,
        cot_seed,
        sender_seed,
    }
}

/// Runs MT sender only with replay context.
#[cfg(target_arch = "wasm32")]
async fn run_sender_with_replay_mt(exec: &mut Session, data: &RecordedDataMt, ot_count: usize) {
    let (cot_send, _) = ideal_rcot(data.cot_seed, data.delta);
    let config = bench_config();
    let mut sender = Sender::new(config, data.sender_seed, cot_send);

    let mut ctx = exec.new_context().unwrap();

    sender.alloc(ot_count).unwrap();
    let output = sender.queue_send_rcot(ot_count).unwrap();
    sender.flush(&mut ctx).await.unwrap();
    let _ = output.await.unwrap();
}

/// Benchmark isolated Ferret sender with MT context and message replay.
///
/// Records receiver->sender messages once during setup using MT contexts,
/// then benchmarks sender execution in isolation using MT replay.
///
/// # Arguments
/// * `n` - Number of iterations
/// * `ot_count` - Number of OTs to generate (e.g., 100000, 1000000, 10000000)
/// * `concurrency` - Maximum parallelism level (max children per parent thread)
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn ferret_sender(n: u32, ot_count: u32, concurrency: u32) -> BenchResult {
    use wasm_bindgen_futures::JsFuture;

    let ot_count_usize = ot_count as usize;

    // Shared slot for benchmark result
    let result: Arc<Mutex<Option<BenchResult>>> = Arc::new(Mutex::new(None));
    let result_clone = result.clone();

    // Run benchmark on web worker thread (where Atomics.wait is allowed)
    let _handle = web_spawn::spawn(move || {
        let bench_result = pollster::block_on(async {
            // Workers don't have `window`, use global scope to get performance
            let global = js_sys::global();
            let performance: web_sys::Performance =
                js_sys::Reflect::get(&global, &"performance".into())
                    .expect("performance should exist")
                    .unchecked_into();

            // Record messages once (not timed)
            let recorded = record_for_sender_mt(0, concurrency as usize, ot_count_usize).await;

            let mut total_elapsed_ms = 0.0;

            for _ in 0..n {
                // Timed section: sender replay with MT context
                let start = performance.now();

                let mut exec = replay_mt_context_with_spawn_and_limit(
                    recorded.data.clone(),
                    max_frame_length(),
                    concurrency as usize,
                    |f| {
                        let _ = web_spawn::spawn(f);
                        Ok(())
                    },
                );
                run_sender_with_replay_mt(&mut exec, &recorded, ot_count_usize).await;

                total_elapsed_ms += performance.now() - start;
            }

            BenchResult {
                elapsed_ms: total_elapsed_ms,
                and_gates: n as u64 * ot_count as u64,
            }
        });
        *result_clone.lock().unwrap() = Some(bench_result);
    });

    // Initial yield to let the worker start
    JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL))
        .await
        .unwrap();

    // Poll for result on main thread (non-blocking)
    loop {
        if let Some(r) = result.lock().unwrap().take() {
            return r;
        }
        // Yield with 10ms delay to avoid busy-spinning
        JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 10)
                .unwrap();
        }))
        .await
        .unwrap();
    }
}
