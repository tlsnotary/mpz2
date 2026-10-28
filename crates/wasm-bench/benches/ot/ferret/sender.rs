//! Browser port of `crates/ot/benches/ferret/sender.rs` (ST + MT).
//!
//! The ST/MT bodies are shared verbatim via `#[path]` from
//! `crates/ot/benches/ferret/support/sender_body.rs`.
//!
//! Run with (from `crates/wasm-bench`):
//!   cargo +nightly bench --bench ot_ferret_sender                  (ST)
//!   cargo +nightly bench --bench ot_ferret_sender --features rayon (MT)

use core::time::Duration;
use std::sync::Arc;

use wasm_bindgen_test::{Criterion, Instant, wasm_bindgen_bench, wasm_bindgen_test_configure};

#[path = "../../../../ot/benches/ferret/support/sender_body.rs"]
#[allow(dead_code)] // The gated-out mode\'s body functions are unused.
mod body;
#[path = "../../support/pools.rs"]
mod pools;

wasm_bindgen_test_configure!(run_in_browser);

// The replay context (and its recorded-data copy) is built in the untimed part
// of `iter_custom_future`, so only `run_*_with_replay` is measured.

/// Single-threaded Ferret sender.
#[cfg(not(feature = "rayon"))]
#[wasm_bindgen_bench]
async fn ferret_sender_st(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    let recorded = Arc::new(body::record_for_sender_st(0, body::OT_COUNT).await);

    c.bench_async_function("ferret/sender_st", move |b| {
        let recorded = recorded.clone();
        Box::pin(b.iter_custom_future(move |iters| {
            let recorded = recorded.clone();
            async move {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    // Setup (untimed).
                    let mut ctx = body::replay_sender_st(recorded.bytes.clone());
                    // Timed.
                    let start = Instant::now();
                    body::run_sender_with_replay_st(&mut ctx, &recorded).await;
                    total += start.elapsed();
                }
                total
            }
        }))
    })
    .await;
}

/// Multi-threaded Ferret sender.
#[cfg(feature = "rayon")]
#[wasm_bindgen_bench]
async fn ferret_sender_mt(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    pools::init_mpz().await;
    pools::init_rayon_worker().await;

    let recorded = Arc::new(body::record_for_sender_mt(0, body::OT_COUNT).await);

    c.bench_async_function("ferret/sender_mt", move |b| {
        let recorded = recorded.clone();
        Box::pin(b.iter_custom_future(move |iters| {
            let recorded = recorded.clone();
            async move {
                // Rayon's `par_*` parks the calling thread, which is illegal on
                // the browser main thread. Run on the persistent rayon worker.
                pools::submit_rayon(move || {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        pools::tick();
                        // Setup (untimed).
                        let mut exec = body::replay_sender_mt(recorded.data.clone());
                        // Timed.
                        let start = Instant::now();
                        futures::executor::block_on(body::run_sender_with_replay_mt(
                            &mut exec, &recorded,
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
