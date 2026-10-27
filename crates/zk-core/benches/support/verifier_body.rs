//! Shared, target-agnostic body for the zk-core verifier benchmarks.
//!
//! Lives in the native bench directory and is included via `#[path]` by both
//! `crates/zk-core/benches/verifier.rs` and
//! `crates/wasm-bench/benches/zk-core/verifier.rs`.

use std::sync::Arc;

use blake3::Hasher;
use mpz_circuits::Circuit;
use mpz_memory_core::correlated::{Delta, Key, Mac};
use mpz_ot_core::{
    ideal::rcot::IdealRCOT,
    rcot::{RCOTReceiverOutput, RCOTSenderOutput},
};
use mpz_zk_core::{Prover, UV, Verifier};
use rand::{RngExt, SeedableRng, rngs::StdRng};

/// Gate-count thresholds for the execute phase, shared by the native criterion
/// bench and the browser harness.
pub const EXECUTE_THRESHOLDS: &[(u64, &str)] =
    &[(100_000, "100K"), (1_000_000, "1M"), (10_000_000, "10M")];

/// Gate-count thresholds for the check phase, shared by the native criterion
/// bench and the browser harness.
pub const CHECK_THRESHOLDS: &[(u64, &str)] =
    &[(200_000, "200K"), (400_000, "400K"), (600_000, "600K")];

/// Correlations and circuit for benchmarking the QuickSilver verifier.
pub struct VerifierBench {
    circuit: Arc<Circuit>,
    circuit_count: usize,
    and_count: usize,
    inputs_per_circuit: usize,
    // Verifier-side inputs.
    input_keys: Vec<Key>,
    gate_keys: Vec<Key>,
    svole_keys: Vec<mpz_core::Block>,
    svole_choices: Vec<bool>,
    svole_ev: Vec<mpz_core::Block>,
    adjustments: Vec<Vec<bool>>,
    // Prover-side inputs, used only by `check_setup` to run the untimed
    // execute.
    input_macs: Vec<Mac>,
    gate_macs: Vec<Mac>,
    gate_masks: Vec<bool>,
    delta: Delta,
}

impl VerifierBench {
    pub fn new(circuit: Arc<Circuit>, circuit_count: usize) -> Self {
        let and_count = circuit.and_count();
        let inputs_per_circuit = circuit.inputs().len();

        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let mut rcot = IdealRCOT::new(rng.random(), delta.into_inner());

        let total_inputs = inputs_per_circuit * circuit_count;
        rcot.alloc(total_inputs);
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput { mut keys, .. },
            RCOTReceiverOutput {
                msgs: mut macs,
                choices,
                ..
            },
        ) = rcot.transfer(total_inputs).unwrap();
        keys.iter_mut().for_each(|key| key.set_lsb(false));
        macs.iter_mut()
            .zip(&choices)
            .for_each(|(mac, &choice)| mac.set_lsb(choice));
        let input_keys = Key::from_blocks(keys);
        let input_macs = Mac::from_blocks(macs);

        let total_and_gates = and_count * circuit_count;
        rcot.alloc(total_and_gates);
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput { keys, .. },
            RCOTReceiverOutput {
                choices: gate_masks,
                msgs: macs,
                ..
            },
        ) = rcot.transfer(total_and_gates).unwrap();
        let gate_keys = Key::from_blocks(keys);
        let gate_macs = Mac::from_blocks(macs);

        rcot.alloc(128);
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput {
                keys: svole_keys, ..
            },
            RCOTReceiverOutput {
                choices: svole_choices,
                msgs: svole_ev,
                ..
            },
        ) = rcot.transfer(128).unwrap();

        // Pre-generate prover adjustments (not timed).
        let adjustments: Vec<Vec<bool>> = {
            let mut prover = Prover::default();
            let mut all = Vec::with_capacity(circuit_count);
            for i in 0..circuit_count {
                let input = i * inputs_per_circuit;
                let gate = i * and_count;
                let mut exec = prover
                    .execute(
                        circuit.clone(),
                        &input_macs[input..input + inputs_per_circuit],
                        &gate_masks[gate..gate + and_count],
                        &gate_macs[gate..gate + and_count],
                    )
                    .unwrap();
                let adj: Vec<bool> = exec.iter().collect();
                let _ = exec.finish().unwrap();
                all.push(adj);
            }
            all
        };

        Self {
            circuit,
            circuit_count,
            and_count,
            inputs_per_circuit,
            input_keys,
            gate_keys,
            svole_keys,
            svole_choices,
            svole_ev,
            adjustments,
            input_macs,
            gate_macs,
            gate_masks,
            delta,
        }
    }

    /// Times the execute phase only (consumes pre-generated adjustments).
    pub fn execute(&self) {
        let mut verifier = Verifier::new(self.delta);
        for i in 0..self.circuit_count {
            let input = i * self.inputs_per_circuit;
            let gate = i * self.and_count;
            let mut exec = verifier
                .execute(
                    self.circuit.clone(),
                    &self.input_keys[input..input + self.inputs_per_circuit],
                    &self.gate_keys[gate..gate + self.and_count],
                )
                .unwrap();
            let mut consumer = exec.consumer();
            for &adjust in &self.adjustments[i] {
                consumer.next(adjust);
            }
            let _ = exec.finish().unwrap();
        }
    }

    /// Runs execute + prover check (untimed) and returns the verifier state for
    /// the timed check.
    pub fn check_setup(&self) -> (Verifier, Hasher, UV) {
        let mut prover = Prover::default();
        let mut verifier = Verifier::new(self.delta);

        for i in 0..self.circuit_count {
            let input = i * self.inputs_per_circuit;
            let gate = i * self.and_count;

            let mut prover_exec = prover
                .execute(
                    self.circuit.clone(),
                    &self.input_macs[input..input + self.inputs_per_circuit],
                    &self.gate_masks[gate..gate + self.and_count],
                    &self.gate_macs[gate..gate + self.and_count],
                )
                .unwrap();
            let mut verifier_exec = verifier
                .execute(
                    self.circuit.clone(),
                    &self.input_keys[input..input + self.inputs_per_circuit],
                    &self.gate_keys[gate..gate + self.and_count],
                )
                .unwrap();

            let mut consumer = verifier_exec.consumer();
            for adjust in prover_exec.iter() {
                consumer.next(adjust);
            }

            let _ = prover_exec.finish().unwrap();
            let _ = verifier_exec.finish().unwrap();
        }

        let mut prover_transcript = Hasher::default();
        let uv = prover
            .check(&mut prover_transcript, &self.svole_choices, &self.svole_ev)
            .unwrap();

        (verifier, Hasher::default(), uv)
    }

    /// Times the check phase only.
    pub fn check_run(&self, verifier: &mut Verifier, transcript: &mut Hasher, uv: UV) {
        verifier.check(transcript, &self.svole_keys, uv).unwrap();
    }
}
