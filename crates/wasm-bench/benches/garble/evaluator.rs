//! Browser port of `crates/garble/benches/evaluator.rs` (ST + MT).
//!
//! The ST/MT bodies are shared verbatim via `#[path]` from
//! `crates/garble/benches/support/evaluator_body.rs`.
//!
//! Run with:
//!   CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
//!     WASM_BINDGEN_TEST_TIMEOUT=1800 WASM_BINDGEN_TEST_DRIVER_TIMEOUT=1800 \
//!     cargo +nightly bench --no-default-features --target
//! wasm32-unknown-unknown \       --bench garble_evaluator
//! -Zbuild-std=panic_abort,std

use core::time::Duration;
use std::sync::Arc;

use mpz_circuits::{AES128, Circuit};
use wasm_bindgen_test::{Criterion, Instant, wasm_bindgen_bench, wasm_bindgen_test_configure};

#[path = "../../../garble/benches/support/evaluator_body.rs"]
#[allow(dead_code)] // The gated-out mode\'s body functions are unused.
mod body;
#[path = "../support/pools.rs"]
mod pools;

wasm_bindgen_test_configure!(run_in_browser);

// The replay context (and its recorded-data copy) is built in the untimed part
// of `iter_custom_future`, so only `run_*_with_replay` is measured.

/// Single-threaded evaluator.
#[cfg(not(feature = "rayon"))]
#[wasm_bindgen_bench]
async fn evaluator_st(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    let circuit: Arc<Circuit> = AES128.clone();
    let gates_per_circuit = circuit.and_count() as u64;

    for &(threshold, name) in body::THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;

        let recorded = body::record_for_evaluator_st(circuit.clone(), circuit_count, 0).await;
        let recorded = Arc::new(recorded);
        let circuit_clone = circuit.clone();

        c.bench_async_function(&format!("evaluator/st/{name}"), move |b| {
            let recorded = recorded.clone();
            let circuit_clone = circuit_clone.clone();
            Box::pin(b.iter_custom_future(move |iters| {
                let recorded = recorded.clone();
                let circuit_clone = circuit_clone.clone();
                async move {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // Setup (untimed).
                        let mut ctx = body::replay_evaluator_st(
                            (*recorded).clone(),
                            circuit_clone.clone(),
                            circuit_count,
                        );
                        // Timed.
                        let start = Instant::now();
                        body::run_evaluator_with_replay_st(
                            &mut ctx,
                            circuit_clone.clone(),
                            circuit_count,
                        )
                        .await;
                        total += start.elapsed();
                    }
                    total
                }
            }))
        })
        .await;
    }
}

/// Multi-threaded evaluator.
#[cfg(feature = "rayon")]
#[wasm_bindgen_bench]
async fn evaluator_mt(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    pools::init_mpz().await;

    let circuit: Arc<Circuit> = AES128.clone();
    let gates_per_circuit = circuit.and_count() as u64;

    for &(threshold, name) in body::THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;

        let recorded_mt = body::record_for_evaluator_mt(circuit.clone(), circuit_count, 0).await;
        let recorded_mt = Arc::new(recorded_mt);
        let circuit_clone = circuit.clone();

        c.bench_async_function(&format!("evaluator/mt/{name}"), move |b| {
            let recorded_mt = recorded_mt.clone();
            let circuit_clone = circuit_clone.clone();
            Box::pin(b.iter_custom_future(move |iters| {
                let recorded_mt = recorded_mt.clone();
                let circuit_clone = circuit_clone.clone();
                async move {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        // Setup (untimed).
                        let mut exec = body::replay_evaluator_mt(
                            (*recorded_mt).clone(),
                            circuit_clone.clone(),
                            circuit_count,
                        );
                        // Timed.
                        let start = Instant::now();
                        body::run_evaluator_with_replay_mt(
                            &mut exec,
                            circuit_clone.clone(),
                            circuit_count,
                        )
                        .await;
                        total += start.elapsed();
                    }
                    total
                }
            }))
        })
        .await;
    }
}
