use core::fmt;
use std::{ops::Range, sync::Arc};

use cfg_if::cfg_if;
use mpz_memory_core::correlated::Mac;

use crate::{DEFAULT_BATCH_SIZE, EncryptedGateBatch, GarbledCircuit, circuit::EncryptedGate};
use mpz_circuits::{Circuit, Gate};
use mpz_core::{
    Block,
    aes::{FIXED_KEY_AES, FixedKeyAes},
};

/// Errors that can occur during garbled circuit evaluation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum EvaluatorError {
    #[error("input length mismatch: expected {expected}, got {actual}")]
    InputLength { expected: usize, actual: usize },
    #[error("evaluator not finished")]
    NotFinished,
}

/// Evaluates half-gate garbled AND gate
#[inline]
pub(crate) fn and_gate(
    cipher: &FixedKeyAes,
    x: &Block,
    y: &Block,
    encrypted_gate: &EncryptedGate,
    gid: usize,
) -> Block {
    let s_a = x.lsb();
    let s_b = y.lsb();

    let j = Block::new((gid as u128).to_be_bytes());
    let k = Block::new(((gid + 1) as u128).to_be_bytes());

    let mut h = [*x, *y];
    cipher.tccr_many(&[j, k], &mut h);

    let [hx, hy] = h;

    let w_g = hx ^ (encrypted_gate[0] & Block::SELECT_MASK[s_a as usize]);
    let w_e = hy ^ (Block::SELECT_MASK[s_b as usize] & (encrypted_gate[1] ^ x));

    w_g ^ w_e
}

/// Output of the evaluator.
#[derive(Debug)]
pub struct EvaluatorOutput {
    /// Output MACs of the circuit.
    pub outputs: Vec<Mac>,
}

/// Garbled circuit evaluator.
#[derive(Debug, Default)]
pub struct Evaluator {
    /// Buffer for the active labels.
    buffer: Vec<Block>,
}

impl Evaluator {
    /// Creates a new evaluator with a buffer of the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Returns a consumer over the encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The input labels to the circuit.
    pub fn evaluate<'a>(
        &'a mut self,
        circ: &'a Circuit,
        inputs: &[Mac],
    ) -> Result<EncryptedGateConsumer<'a, std::slice::Iter<'a, Gate>>, EvaluatorError> {
        if inputs.len() != circ.inputs().len() {
            return Err(EvaluatorError::InputLength {
                expected: circ.inputs().len(),
                actual: inputs.len(),
            });
        }

        // Expand the buffer to fit the circuit
        if circ.feed_count() > self.buffer.len() {
            self.buffer.resize(circ.feed_count(), Default::default());
        }

        self.buffer[..inputs.len()].copy_from_slice(Mac::as_blocks(inputs));

        Ok(EncryptedGateConsumer::new(
            circ.gates().iter(),
            &mut self.buffer,
            circ.and_count(),
            circ.outputs(),
        ))
    }

    /// Returns a consumer over batched encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The input labels to the circuit.
    pub fn evaluate_batched<'a>(
        &'a mut self,
        circ: &'a Circuit,
        inputs: &[Mac],
    ) -> Result<EncryptedGateBatchConsumer<'a, std::slice::Iter<'a, Gate>>, EvaluatorError> {
        self.evaluate(circ, inputs).map(EncryptedGateBatchConsumer)
    }
}

/// Consumer over the encrypted gates of a circuit.
pub struct EncryptedGateConsumer<'a, I: Iterator> {
    /// Cipher to use to encrypt the gates.
    cipher: &'static FixedKeyAes,
    /// Buffer for the active labels.
    labels: &'a mut [Block],
    /// Iterator over the gates.
    gates: I,
    /// Current gate id.
    gid: usize,
    /// Number of AND gates evaluated.
    counter: usize,
    /// Total number of AND gates in the circuit.
    and_count: usize,
    /// Range of the outputs in the buffer.
    outputs: Range<usize>,
    /// Whether the entire circuit has been garbled.
    complete: bool,
}

impl<I: Iterator> fmt::Debug for EncryptedGateConsumer<'_, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptedGateConsumer {{ .. }}")
    }
}

impl<'a, I> EncryptedGateConsumer<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    fn new(gates: I, labels: &'a mut [Block], and_count: usize, outputs: Range<usize>) -> Self {
        Self {
            cipher: &(*FIXED_KEY_AES),
            gates,
            labels,
            gid: 1,
            counter: 0,
            and_count,
            outputs,
            complete: false,
        }
    }

    /// Returns `true` if the evaluator wants more encrypted gates.
    #[inline]
    pub fn wants_gates(&self) -> bool {
        self.counter != self.and_count
    }

    /// Evaluates the next encrypted gate in the circuit.
    #[inline]
    pub fn next(&mut self, encrypted_gate: EncryptedGate) {
        while let Some(gate) = self.gates.next() {
            match gate {
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x = self.labels[node_x.id()];
                    let y = self.labels[node_y.id()];
                    self.labels[node_z.id()] = x ^ y;
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x = self.labels[node_x.id()];
                    let y = self.labels[node_y.id()];
                    let z = and_gate(self.cipher, &x, &y, &encrypted_gate, self.gid);
                    self.labels[node_z.id()] = z;

                    self.gid += 2;
                    self.counter += 1;

                    // If we have more AND gates to evaluate, return.
                    if self.wants_gates() {
                        return;
                    }
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let x = self.labels[node_x.id()];
                    self.labels[node_z.id()] = x;
                }
                Gate::Id {
                    x: node_x,
                    z: node_z,
                } => {
                    let x = self.labels[node_x.id()];
                    self.labels[node_z.id()] = x;
                }
            }
        }

        self.complete = true;
    }

    /// Returns the encoded outputs of the circuit.
    pub fn finish(mut self) -> Result<EvaluatorOutput, EvaluatorError> {
        if self.wants_gates() {
            return Err(EvaluatorError::NotFinished);
        }

        // If there were 0 AND gates in the circuit, we need to evaluate the
        // "free" gates now.
        if !self.complete {
            self.next(Default::default());
        }

        Ok(EvaluatorOutput {
            outputs: Mac::from_blocks(self.labels[self.outputs].to_vec()),
        })
    }
}

/// Consumer returned by [`Evaluator::evaluate_batched`].
#[derive(Debug)]
pub struct EncryptedGateBatchConsumer<'a, I: Iterator, const N: usize = DEFAULT_BATCH_SIZE>(
    EncryptedGateConsumer<'a, I>,
);

impl<'a, I, const N: usize> EncryptedGateBatchConsumer<'a, I, N>
where
    I: Iterator<Item = &'a Gate>,
{
    /// Returns `true` if the evaluator wants more encrypted gates.
    pub fn wants_gates(&self) -> bool {
        self.0.wants_gates()
    }

    /// Evaluates the next batch of gates in the circuit.
    #[inline]
    pub fn next(&mut self, batch: EncryptedGateBatch<N>) {
        for encrypted_gate in batch.into_array() {
            self.0.next(encrypted_gate);
            if !self.0.wants_gates() {
                // Skipping any remaining gates which may have been used to pad
                // the last batch.
                return;
            }
        }
    }

    /// Returns the encoded outputs of the circuit, and the hash of the
    /// encrypted gates if present.
    pub fn finish(self) -> Result<EvaluatorOutput, EvaluatorError> {
        self.0.finish()
    }
}

/// Evaluates multiple garbled circuits in bulk.
pub fn evaluate_garbled_circuits(
    circs: Vec<(Arc<Circuit>, Vec<Mac>, GarbledCircuit)>,
) -> Result<Vec<EvaluatorOutput>, EvaluatorError> {
    cfg_if! {
        if #[cfg(feature = "rayon")] {
            use rayon::prelude::*;

            circs.into_par_iter().map(|(circ, inputs, garbled_circuit)| {
                let mut ev = Evaluator::with_capacity(circ.feed_count());
                let mut consumer = ev.evaluate(&circ, &inputs)?;
                for gate in garbled_circuit.gates {
                    consumer.next(gate);
                }
                consumer.finish()
            }).collect::<Result<Vec<_>, _>>()
        } else {
            let mut ev = Evaluator::default();
            let mut outputs = Vec::with_capacity(circs.len());
            for (circ, inputs, garbled_circuit) in circs {
                let mut consumer = ev.evaluate(&circ, &inputs)?;
                for gate in garbled_circuit.gates {
                    consumer.next(gate);
                }
                outputs.push(consumer.finish()?);
            }

            Ok(outputs)
        }
    }
}
