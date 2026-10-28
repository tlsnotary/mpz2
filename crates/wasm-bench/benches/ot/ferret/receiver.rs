//! Browser port of `crates/ot/benches/ferret/receiver.rs` (ST + MT).
//!
//! The ST/MT bodies are shared verbatim via `#[path]` from
//! `crates/ot/benches/ferret/support/receiver_body.rs`.
//!
//! Run with:
//!   CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
//!     WASM_BINDGEN_TEST_TIMEOUT=1800 WASM_BINDGEN_TEST_DRIVER_TIMEOUT=1800 \
//!     cargo +nightly bench --no-default-features --target
//! wasm32-unknown-unknown \       --bench ot_ferret_receiver
//! -Zbuild-std=panic_abort,std

use core::time::Duration;
use std::sync::Arc;

use wasm_bindgen_test::{Criterion, Instant, wasm_bindgen_bench, wasm_bindgen_test_configure};

#[path = "../../../../ot/benches/ferret/support/receiver_body.rs"]
#[allow(dead_code)] // The gated-out mode\'s body functions are unused.
mod body;
#[path = "../../support/pools.rs"]
mod pools;

wasm_bindgen_test_configure!(run_in_browser);

// The replay context (and its recorded-data copy) is built in the untimed part
// of `iter_custom_future`, so only `run_*_with_replay` is measured.

/// Single-threaded Ferret receiver.
#[cfg(not(feature = "rayon"))]
#[wasm_bindgen_bench]
async fn ferret_receiver_st(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    let recorded = Arc::new(body::record_for_receiver_st(0, body::OT_COUNT).await);

    c.bench_async_function("ferret/receiver_st", move |b| {
        let recorded = recorded.clone();
        Box::pin(b.iter_custom_future(move |iters| {
            let recorded = recorded.clone();
            async move {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    // Setup (untimed).
                    let mut ctx = body::replay_receiver_st(recorded.bytes.clone());
                    // Timed.
                    let start = Instant::now();
                    body::run_receiver_with_replay_st(&mut ctx, &recorded).await;
                    total += start.elapsed();
                }
                total
            }
        }))
    })
    .await;
}

/// Multi-threaded Ferret receiver.
#[cfg(feature = "rayon")]
#[wasm_bindgen_bench]
async fn ferret_receiver_mt(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    pools::init_mpz().await;

    let recorded = Arc::new(body::record_for_receiver_mt(0, body::OT_COUNT).await);

    c.bench_async_function("ferret/receiver_mt", move |b| {
        let recorded = recorded.clone();
        Box::pin(b.iter_custom_future(move |iters| {
            let recorded = recorded.clone();
            async move {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    // Setup (untimed).
                    let mut exec = body::replay_receiver_mt(recorded.data.clone());
                    // Timed.
                    let start = Instant::now();
                    body::run_receiver_with_replay_mt(&mut exec, &recorded).await;
                    total += start.elapsed();
                }
                total
            }
        }))
    })
    .await;
}
