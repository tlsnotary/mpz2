//! Benchmarks for mpz-garble-core garbler primitives.
//!
//! Measures raw half-gates garbling performance without protocol overhead.

use wasm_bindgen::prelude::*;

use mpz_circuits::AES128;
use mpz_garble_core::{Garbler, Key};
use mpz_memory_core::correlated::Delta;
use rand::{RngExt, SeedableRng, rngs::StdRng};

/// Shared benchmark state, initialized once.
struct BenchState {
    delta: Delta,
    inputs: Vec<Key>,
}

impl BenchState {
    fn new() -> Self {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();

        Self { delta, inputs }
    }
}

thread_local! {
    static STATE: BenchState = BenchState::new();
}

/// Returns the number of AND gates in the AES-128 circuit.
#[wasm_bindgen]
pub fn garble_core_aes128_and_count() -> u32 {
    AES128.and_count() as u32
}

/// Benchmark half-gates garbling: garble AES circuit n times.
/// Returns a checksum to prevent optimization.
#[wasm_bindgen]
pub fn garble_core_half_gates_garble(n: u32) -> u32 {
    STATE.with(|state| {
        let mut gb = Garbler::default();
        let mut checksum = 0u32;

        for _ in 0..n {
            let mut iter = gb.generate(&AES128, state.delta, &state.inputs).unwrap();
            let gates: Vec<_> = iter.by_ref().collect();
            let _ = iter.finish().unwrap();
            checksum = checksum.wrapping_add(gates.len() as u32);
        }

        checksum
    })
}
