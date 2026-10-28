//! Browser port of `crates/zk/benches/prover.rs`.
//!
//! The benchmark bodies are shared verbatim via `#[path]` from
//! `crates/zk/benches/support/prover_body.rs`.
//!
//! Run with:
//!   CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
//!     WASM_BINDGEN_TEST_TIMEOUT=1800 WASM_BINDGEN_TEST_DRIVER_TIMEOUT=1800 \
//!     cargo +nightly bench --no-default-features --target
//! wasm32-unknown-unknown \       --bench zk_prover -Zbuild-std=panic_abort,std

#[cfg(feature = "rayon")]
use core::time::Duration;

use mpz_circuits::AES128;
#[cfg(feature = "rayon")]
use wasm_bindgen_test::Instant;
use wasm_bindgen_test::{Criterion, wasm_bindgen_bench, wasm_bindgen_test_configure};

#[path = "../../../zk/benches/support/prover_body.rs"]
#[allow(dead_code)] // The gated-out mode\'s body functions are unused.
mod body;
#[path = "../support/pools.rs"]
mod pools;

wasm_bindgen_test_configure!(run_in_browser);

// Thresholds come from the shared body. The runner kills the browser if a test
// exceeds its default timeout, so the larger sizes need a raised
// `WASM_BINDGEN_TEST_TIMEOUT` (and `WASM_BINDGEN_TEST_DRIVER_TIMEOUT`), e.g.
// 1800.

/// Multi-threaded prover (`prover/mt/*`).
#[cfg(feature = "rayon")]
#[wasm_bindgen_bench]
async fn prover_mt(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    // Starts web_spawn and installs the global pool whose workers the MT replay
    // sessions run on.
    pools::init_mpz().await;
    pools::init_rayon_worker().await;

    let and_count = AES128.and_count();
    for &(gate_count, name) in body::THRESHOLDS {
        let circuit_count = (gate_count as usize).div_ceil(and_count);

        // Record once (not timed).
        let recorded = body::record_for_prover_mt(circuit_count, 0).await;

        c.bench_async_function(&format!("prover/mt/{name}"), move |b| {
            let recorded = recorded.clone();
            Box::pin(b.iter_custom_future(move |iters| {
                let recorded = recorded.clone();
                async move {
                    pools::submit_rayon(move || {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            pools::tick();
                            let mut exec = body::replay_prover_mt(recorded.clone(), circuit_count);
                            let start = Instant::now();
                            futures::executor::block_on(body::run_prover_with_replay_mt(
                                &mut exec,
                                circuit_count,
                            ));
                            total += start.elapsed();
                        }
                        total
                    })
                    .await
                }
            }))
        })
        .await;
    }
}

/// Single-threaded prover (`prover/st/*`). No workers/global pool required;
/// the futures are driven by the JS event loop.
#[cfg(not(feature = "rayon"))]
#[wasm_bindgen_bench]
async fn prover_st(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    let and_count = AES128.and_count();
    for &(gate_count, name) in body::THRESHOLDS {
        let circuit_count = (gate_count as usize).div_ceil(and_count);

        // Record once (not timed).
        let recorded = body::record_for_prover_st(circuit_count, 0).await;

        c.bench_async_function(&format!("prover/st/{name}"), move |b| {
            let recorded = recorded.clone();
            Box::pin(b.iter_future(move || {
                let recorded = recorded.clone();
                async move {
                    let mut ctx = body::replay_prover_st(recorded, circuit_count);
                    body::run_prover_with_replay_st(&mut ctx, circuit_count).await;
                }
            }))
        })
        .await;
    }
}
