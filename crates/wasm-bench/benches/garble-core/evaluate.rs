//! Browser port of `crates/garble-core/benches/evaluate.rs`.
//!
//! Scenarios shared verbatim via `#[path]` from
//! `crates/garble-core/benches/support/evaluate_body.rs`.

use core::time::Duration;
use std::sync::Arc;

use mpz_circuits::AES128;
use wasm_bindgen_test::{Criterion, Instant, wasm_bindgen_bench, wasm_bindgen_test_configure};

#[path = "../../../garble-core/benches/support/evaluate_body.rs"]
#[allow(dead_code)] // The gated-out mode's body functions are unused.
mod body;
#[cfg(feature = "rayon")]
#[path = "../support/pools.rs"]
mod pools;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_bench]
fn evaluate(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    let gates_per_circuit = AES128.and_count() as u64;

    for &(threshold, name) in body::THRESHOLDS {
        let iterations = threshold.div_ceil(gates_per_circuit) as usize;

        let mut iter_bench = body::EvaluateBench::new(iterations);
        c.bench_function(&format!("evaluate/iter/{name}"), |b| {
            b.iter(|| iter_bench.run_iter());
        });

        let mut batched_bench = body::EvaluateBench::new(iterations);
        c.bench_function(&format!("evaluate/batched/{name}"), |b| {
            b.iter(|| batched_bench.run_batched());
        });
    }
}

/// Bulk evaluation across many circuits (`evaluate_garbled_circuits`).
///
/// The scenario is the same with or without `rayon`; only the execution
/// strategy differs. Without the feature the bulk helper is a serial loop and
/// runs on the main thread. With it, `par_*` parks the caller, so each sample
/// runs on the persistent rayon worker instead.
#[wasm_bindgen_bench]
async fn evaluate_bulk(_c: &mut Criterion) {
    // Native benches use sample_size(10); the macro's criterion can't be
    // reconfigured.
    let mut c = Criterion::default()
        .with_location(file!(), module_path!())
        .sample_size(10);

    #[cfg(feature = "rayon")]
    pools::init_rayon_worker().await;

    let gates_per_circuit = AES128.and_count() as u64;

    for &(threshold, name) in body::THRESHOLDS {
        let circuit_count = threshold.div_ceil(gates_per_circuit) as usize;
        let bench = Arc::new(body::EvaluateParallelBench::new(circuit_count));

        c.bench_async_function(&format!("evaluate/bulk/{name}"), move |b| {
            let bench = bench.clone();
            Box::pin(b.iter_custom_future(move |iters| {
                let bench = bench.clone();
                async move {
                    // `par_*` parks its caller, which is illegal on the main
                    // thread, so run the sample on the persistent worker.
                    #[cfg(feature = "rayon")]
                    let total = pools::submit_rayon(move || run_bulk_iters(iters, &bench)).await;
                    // Serial bulk evaluation is safe on the main thread.
                    #[cfg(not(feature = "rayon"))]
                    let total = run_bulk_iters(iters, &bench);

                    total
                }
            }))
        })
        .await;
    }
}

/// Runs `iters` bulk evaluations, self-timing only the evaluation itself.
fn run_bulk_iters(iters: u64, bench: &body::EvaluateParallelBench) -> Duration {
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        #[cfg(feature = "rayon")]
        pools::tick();
        // Setup (building the per-circuit inputs) is untimed.
        let circs = bench.circs();
        let start = Instant::now();
        body::evaluate(circs);
        total += start.elapsed();
    }
    total
}
