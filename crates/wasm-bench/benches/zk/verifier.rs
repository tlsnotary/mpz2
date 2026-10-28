//! Browser port of `crates/zk/benches/verifier.rs`.
//!
//! The benchmark bodies are shared verbatim via `#[path]` from
//! `crates/zk/benches/support/verifier_body.rs`.
//!
//! Run with:
//!   CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
//!     WASM_BINDGEN_TEST_TIMEOUT=1800 WASM_BINDGEN_TEST_DRIVER_TIMEOUT=1800 \
//!     cargo +nightly bench --no-default-features --target
//! wasm32-unknown-unknown \       --bench zk_verifier
//! -Zbuild-std=panic_abort,std

use mpz_circuits::AES128;
use wasm_bindgen_test::{Criterion, wasm_bindgen_bench, wasm_bindgen_test_configure};

#[path = "../../../zk/benches/support/verifier_body.rs"]
#[allow(dead_code)] // The gated-out mode\'s body functions are unused.
mod body;
#[path = "../support/pools.rs"]
mod pools;

wasm_bindgen_test_configure!(run_in_browser);

// Thresholds come from the shared body. The runner kills the browser if a test
// exceeds its default timeout, so the larger sizes need a raised
// `WASM_BINDGEN_TEST_TIMEOUT` (and `WASM_BINDGEN_TEST_DRIVER_TIMEOUT`), e.g.
// 1800.

/// Multi-threaded verifier (`verifier/mt/*`).
#[cfg(feature = "rayon")]
#[wasm_bindgen_bench]
async fn verifier_mt(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    // Starts web_spawn and installs the global pool whose workers the MT replay
    // sessions run on.
    pools::init_mpz().await;

    let and_count = AES128.and_count();
    for &(gate_count, name) in body::THRESHOLDS {
        let circuit_count = (gate_count as usize).div_ceil(and_count);

        // Record once (not timed).
        let (recorded, ot_seed, delta) = body::record_for_verifier_mt(circuit_count, 0).await;

        c.bench_async_function(&format!("verifier/mt/{name}"), move |b| {
            let recorded = recorded.clone();
            Box::pin(b.iter_future(move || {
                let recorded = recorded.clone();
                async move {
                    let mut exec = body::replay_verifier_mt(recorded, circuit_count);
                    body::run_verifier_with_replay_mt(&mut exec, circuit_count, delta, ot_seed)
                        .await;
                }
            }))
        })
        .await;
    }
}

/// Single-threaded verifier (`verifier/st/*`). No workers/global pool required;
/// the futures are driven by the JS event loop.
#[cfg(not(feature = "rayon"))]
#[wasm_bindgen_bench]
async fn verifier_st(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    let and_count = AES128.and_count();
    for &(gate_count, name) in body::THRESHOLDS {
        let circuit_count = (gate_count as usize).div_ceil(and_count);

        // Record once (not timed).
        let (recorded, ot_seed, delta) = body::record_for_verifier_st(circuit_count, 0).await;

        c.bench_async_function(&format!("verifier/st/{name}"), move |b| {
            let recorded = recorded.clone();
            Box::pin(b.iter_future(move || {
                let recorded = recorded.clone();
                async move {
                    let mut ctx = body::replay_verifier_st(recorded, circuit_count);
                    body::run_verifier_with_replay_st(&mut ctx, circuit_count, delta, ot_seed)
                        .await;
                }
            }))
        })
        .await;
    }
}
