//! Benchmarks for mpz-garble-core evaluator primitives.
//!
//! Measures raw half-gates evaluation performance without protocol overhead.

use wasm_bindgen::prelude::*;

use mpz_circuits::{AES128, Circuit};
use mpz_garble_core::{EncryptedGate, Evaluator, GarbledCircuit, Garbler, Key};
use mpz_memory_core::correlated::{Delta, Mac};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::sync::Arc;

use crate::BenchResult;

/// Shared benchmark state, initialized once.
struct BenchState {
    delta: Delta,
    inputs: Vec<Key>,
    eval_inputs: Vec<Mac>,
    gates: Vec<EncryptedGate>,
    // Note: batches are regenerated per iteration since EncryptedGateBatch doesn't impl Clone
}

impl BenchState {
    fn new() -> Self {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();
        let choices: Vec<bool> = (0..256).map(|_| rng.random()).collect();

        let eval_inputs: Vec<_> = inputs
            .iter()
            .zip(&choices)
            .map(|(k, &c)| k.auth(c, &delta))
            .collect();

        // Pre-garble circuit for evaluation benchmarks (single gates)
        let mut gb = Garbler::default();
        let mut iter = gb.generate(&AES128, delta, &inputs).unwrap();
        let gates: Vec<_> = iter.by_ref().collect();
        let _ = iter.finish().unwrap();

        Self {
            delta,
            inputs,
            eval_inputs,
            gates,
        }
    }
}

thread_local! {
    static STATE: BenchState = BenchState::new();
}

/// Benchmark half-gates evaluation (iterator): evaluate AES circuit n times.
/// Uses single-gate iterator interface.
/// Returns elapsed time and AND gates processed.
#[wasm_bindgen]
pub fn garble_core_half_gates_evaluate(n: u32) -> BenchResult {
    let performance = web_sys::window().unwrap().performance().unwrap();
    let and_count = AES128.and_count() as u64;

    STATE.with(|state| {
        let start = performance.now();

        let mut ev = Evaluator::default();
        for _ in 0..n {
            let mut consumer = ev.evaluate(&AES128, &state.eval_inputs).unwrap();
            for gate in &state.gates {
                consumer.next(*gate);
            }
            let _ = consumer.finish().unwrap();
        }

        BenchResult {
            elapsed_ms: performance.now() - start,
            and_gates: n as u64 * and_count,
        }
    })
}

/// Benchmark half-gates evaluation (batched): evaluate AES circuit n times.
/// Uses batched gate interface for better throughput.
/// Returns elapsed time and AND gates processed.
#[wasm_bindgen]
pub fn garble_core_half_gates_evaluate_batched(n: u32) -> BenchResult {
    let performance = web_sys::window().unwrap().performance().unwrap();
    let and_count = AES128.and_count() as u64;

    STATE.with(|state| {
        let mut total_elapsed = 0.0;
        let mut ev = Evaluator::default();

        for _ in 0..n {
            // Regenerate batches for this iteration (untimed)
            // EncryptedGateBatch doesn't implement Clone, so we must regenerate
            let mut gb = Garbler::default();
            let mut iter = gb
                .generate_batched(&AES128, state.delta, &state.inputs)
                .unwrap();
            let batches: Vec<_> = iter.by_ref().collect();
            let _ = iter.finish().unwrap();

            // Time only the evaluation
            let start = performance.now();
            let mut consumer = ev.evaluate_batched(&AES128, &state.eval_inputs).unwrap();
            for batch in batches {
                consumer.next(batch);
            }
            let _ = consumer.finish().unwrap();
            total_elapsed += performance.now() - start;
        }

        BenchResult {
            elapsed_ms: total_elapsed,
            and_gates: n as u64 * and_count,
        }
    })
}

// Circuit count thresholds for parallel evaluation
#[cfg(target_arch = "wasm32")]
const PARALLEL_THRESHOLDS: &[usize] = &[100, 200, 400];

/// Benchmark parallel circuit evaluation using rayon.
/// Evaluates multiple AES circuits in parallel.
/// Setup (untimed): garble circuits.
/// Timed: only the parallel evaluation phase.
///
/// Runs on a Web Worker because rayon's Atomics.wait is forbidden on main
/// thread.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn garble_core_half_gates_evaluate_parallel(n: u32, concurrency: u32) -> BenchResult {
    use std::sync::Mutex;
    use wasm_bindgen_futures::JsFuture;

    let result: Arc<Mutex<Option<BenchResult>>> = Arc::new(Mutex::new(None));
    let result_clone = result.clone();

    let _handle = web_spawn::spawn(move || {
        // Create a local thread pool (don't use build_global which fails if
        // pool exists)
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(concurrency as usize)
            .spawn_handler(|thread| {
                let _ = web_spawn::spawn(move || thread.run());
                Ok(())
            })
            .build()
            .expect("failed to build rayon pool");

        let bench_result = pool.install(|| {
            use rayon::prelude::*;

            let global = js_sys::global();
            let performance: web_sys::Performance =
                js_sys::Reflect::get(&global, &"performance".into())
                    .expect("performance should exist")
                    .unchecked_into();

            let circuit: Arc<Circuit> = AES128.clone();
            let and_count = circuit.and_count();

            let mut total_eval_time = 0.0;
            let mut total_gates = 0u64;

            // Setup: generate keys and macs once
            let mut rng = StdRng::seed_from_u64(0);
            let delta = Delta::random(&mut rng);
            let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();
            let choices: Vec<bool> = (0..256).map(|_| rng.random()).collect();
            let eval_inputs: Vec<Mac> = inputs
                .iter()
                .zip(&choices)
                .map(|(k, &c)| k.auth(c, &delta))
                .collect();

            for &circuit_count in PARALLEL_THRESHOLDS {
                // Pre-garble circuits for this threshold (untimed)
                let mut garbled_circuits = Vec::with_capacity(circuit_count);
                for _ in 0..circuit_count {
                    let mut gb = Garbler::default();
                    let mut iter = gb.generate(&AES128, delta, &inputs).unwrap();
                    let gates: Vec<_> = iter.by_ref().collect();
                    let _ = iter.finish().unwrap();
                    garbled_circuits.push(GarbledCircuit { gates });
                }

                for _ in 0..n {
                    // Build input for parallel evaluation
                    let circs: Vec<_> = garbled_circuits
                        .iter()
                        .map(|gc| (circuit.clone(), eval_inputs.clone(), gc.clone()))
                        .collect();

                    // Timed: parallel evaluation using par_iter directly in
                    // local pool
                    let start = performance.now();
                    let _outputs: Vec<_> = circs
                        .into_par_iter()
                        .map(|(circ, inputs, garbled_circuit)| {
                            let mut ev = Evaluator::with_capacity(circ.feed_count());
                            let mut consumer = ev.evaluate(&circ, &inputs).unwrap();
                            for gate in garbled_circuit.gates {
                                consumer.next(gate);
                            }
                            consumer.finish().unwrap()
                        })
                        .collect();
                    total_eval_time += performance.now() - start;
                }

                total_gates += n as u64 * circuit_count as u64 * and_count as u64;
            }

            BenchResult {
                elapsed_ms: total_eval_time,
                and_gates: total_gates,
            }
        });
        *result_clone.lock().unwrap() = Some(bench_result);
    });

    // Poll for result from main thread
    loop {
        JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL))
            .await
            .unwrap();
        if let Some(r) = result.lock().unwrap().take() {
            return r;
        }
        // Small delay before next poll
        let promise = js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 10)
                .unwrap();
        });
        JsFuture::from(promise).await.unwrap();
    }
}
