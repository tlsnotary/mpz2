use std::sync::{Arc, Mutex};

use blake3::Hasher;
use mpz_circuits::{Circuit, Gate};
use mpz_core::{Block, bitvec::BitVec};
use mpz_memory_core::correlated::Mac;

use crate::{
    check::{Check, CheckError, Triple, UV},
    store::ProverStoreError,
};

type Result<T> = core::result::Result<T, ProverError>;

#[derive(Debug, Default)]
pub struct Prover {
    check: Arc<Mutex<Check>>,
}

impl Prover {
    pub fn execute<'a>(
        &mut self,
        circ: Arc<Circuit>,
        input_macs: &'a [Mac],
        gate_masks: &'a [bool],
        gate_macs: &'a [Mac],
    ) -> Result<ProverExecute> {
        if input_macs.len() != circ.inputs().len() {
            return Err(ErrorRepr::InputMacCount {
                expected: circ.inputs().len(),
                actual: input_macs.len(),
            }
            .into());
        } else if gate_masks.len() != circ.and_count() {
            return Err(ErrorRepr::GateMaskCount {
                expected: circ.and_count(),
                actual: gate_masks.len(),
            }
            .into());
        } else if gate_macs.len() != circ.and_count() {
            return Err(ErrorRepr::GateMacCount {
                expected: circ.and_count(),
                actual: gate_macs.len(),
            }
            .into());
        }

        let check_idx = self.check.lock().unwrap().reserve(circ.and_count());

        Ok(ProverExecute::new(
            circ,
            input_macs.to_vec(),
            gate_masks.to_vec(),
            gate_macs.to_vec(),
            self.check.clone(),
            check_idx,
        ))
    }

    /// Returns `true` if there are gates to check.
    pub fn wants_check(&self) -> bool {
        self.check.lock().unwrap().wants_check()
    }

    /// Executes the consistency check.
    pub fn check(
        &mut self,
        transcript: &mut Hasher,
        svole_choices: &[bool],
        svole_ev: &[Block],
    ) -> Result<UV> {
        if Arc::strong_count(&self.check) > 1 {
            return Err(ErrorRepr::Inprogress.into());
        }

        self.check
            .lock()
            .unwrap()
            .check_prover(transcript, svole_choices, svole_ev)
            .map_err(From::from)
    }

    /// Returns the number of pending gates that need to be checked.
    pub fn pending(&self) -> usize {
        self.check.lock().unwrap().total()
    }
}

/// Prover circuit execution.
#[derive(Debug)]
pub struct ProverExecute {
    circ: Arc<Circuit>,
    macs: Vec<Mac>,
    triples: Vec<Triple>,
    adjust: BitVec,
    gate_masks: Vec<bool>,
    gate_macs: Vec<Mac>,
    check: Arc<Mutex<Check>>,
    check_idx: usize,

    counter: usize,
    and_count: usize,
}

impl ProverExecute {
    fn new(
        circ: Arc<Circuit>,
        macs: Vec<Mac>,
        gate_masks: Vec<bool>,
        gate_macs: Vec<Mac>,
        check: Arc<Mutex<Check>>,
        check_idx: usize,
    ) -> Self {
        let and_count = circ.and_count();
        Self {
            circ,
            macs,
            triples: Vec::default(),
            adjust: BitVec::default(),
            gate_masks,
            gate_macs,
            check,
            check_idx,
            counter: 0,
            and_count,
        }
    }

    /// Returns the number of AND gates.
    pub fn and_count(&self) -> usize {
        self.circ.and_count()
    }

    /// Returns an iterator which processes each gate in the circuit.
    pub fn iter(&mut self) -> ProverIter<'_, std::slice::Iter<'_, Gate>> {
        // Allocate space for all the MACs.
        self.macs
            .resize_with(self.circ.feed_count(), Default::default);

        if self.triples.capacity() < self.circ.and_count() {
            self.triples.reserve_exact(self.circ.and_count());
        }

        if self.adjust.capacity() < self.circ.and_count() {
            self.adjust.reserve_exact(self.circ.and_count());
        }

        // Reset counter in case this is called multiple times by mistake.
        self.counter = 0;

        ProverIter {
            macs: &mut self.macs,
            gate_masks: &self.gate_masks,
            gate_macs: &self.gate_macs,
            gates: self.circ.gates().iter(),
            triples: &mut self.triples,
            adjust: &mut self.adjust,
            counter: &mut self.counter,
            and_count: self.and_count,
        }
    }

    pub fn finish(self) -> Result<Vec<Mac>> {
        if self.counter != self.and_count {
            return Err(ErrorRepr::Incomplete.into());
        }

        // Flush check state.
        self.check
            .lock()
            .unwrap()
            .write(self.check_idx, &self.triples, &self.adjust);

        Ok(self.macs[self.circ.outputs()].to_vec())
    }
}

/// Iterator yielding adjustment bits for each AND gate.
#[must_use = "iterator does nothing unless consumed"]
pub struct ProverIter<'a, I> {
    macs: &'a mut [Mac],
    gate_masks: &'a [bool],
    gate_macs: &'a [Mac],
    gates: I,
    triples: &'a mut Vec<Triple>,
    adjust: &'a mut BitVec,
    counter: &'a mut usize,
    and_count: usize,
}

impl<'a, I> Iterator for ProverIter<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    type Item = bool;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(gate) = self.gates.next() {
            match gate {
                Gate::Xor { x, y, z } => {
                    let mac_x = self.macs[x.id()];
                    let mac_y = self.macs[y.id()];
                    self.macs[z.id()] = mac_x + mac_y;
                }
                Gate::And { x, y, z } => {
                    let mac_x = self.macs[x.id()];
                    let mac_y = self.macs[y.id()];
                    let mut mac_z = self.gate_macs[*self.counter];

                    // By convention, the LSB of a MAC must contain the value of
                    // the authenticated bit. The verifier
                    // must set LSB(key) == 0 and LSB(delta)
                    // == 1.
                    let w_z = mac_x.pointer() & mac_y.pointer();
                    mac_z.set_pointer(w_z);

                    let adjust = self.gate_masks[*self.counter] ^ w_z;

                    self.macs[z.id()] = mac_z;
                    self.triples.push(Triple {
                        x: mac_x.into(),
                        y: mac_y.into(),
                        z: mac_z.into(),
                    });
                    self.adjust.push(adjust);
                    *self.counter += 1;

                    // If we have processed all AND gates, we can compute
                    // the rest of the "free" gates.
                    if *self.counter >= self.and_count {
                        assert!(self.next().is_none());
                    }

                    return Some(adjust);
                }
                Gate::Inv { x, z } => {
                    let mut mac = self.macs[x.id()];
                    mac.set_pointer(!mac.pointer());
                    self.macs[z.id()] = mac;
                }
                Gate::Id { x, z } => {
                    let mac = self.macs[x.id()];
                    self.macs[z.id()] = mac;
                }
            }
        }

        None
    }
}

#[derive(Debug, thiserror::Error)]
#[error("prover error: {0}")]
pub struct ProverError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("incorrect number of input MACs: expected {expected}, actual {actual}")]
    InputMacCount { expected: usize, actual: usize },
    #[error("incorrect number of gate masks: expected {expected}, actual {actual}")]
    GateMaskCount { expected: usize, actual: usize },
    #[error("incorrect number of gate MACs: expected {expected}, actual {actual}")]
    GateMacCount { expected: usize, actual: usize },
    #[error("execution is incomplete")]
    Incomplete,
    #[error("cannot run consistency check while execution is in progress")]
    Inprogress,
    #[error(transparent)]
    Check(CheckError),
    #[error("cannot return Macs: {0}")]
    Macs(ProverStoreError),
}

impl From<CheckError> for ProverError {
    fn from(err: CheckError) -> Self {
        Self(ErrorRepr::Check(err))
    }
}

impl From<ProverStoreError> for ProverError {
    fn from(value: ProverStoreError) -> Self {
        Self(ErrorRepr::Macs(value))
    }
}
