//! ROLE receiver.

use std::collections::VecDeque;

use hybrid_array::Array;

use mpz_common::future::{MaybeDone, Sender as OutputSender, new_output};
use mpz_fields::Field;
use mpz_ot_core::rot::{ROTReceiver, ROTReceiverOutput};

use crate::{OLEId, OLEShare, ROLEReceiver, ROLEReceiverOutput, SenderMasks};

#[derive(Debug)]
struct Queued<F> {
    count: usize,
    sender: OutputSender<ROLEReceiverOutput<F>>,
}

/// ROLE receiver wrapping a random OT receiver.
#[derive(Debug)]
pub struct Receiver<T, F> {
    id: OLEId,
    alloc: usize,
    /// The total count of ROLEs in the `queue`.
    pending: usize,
    queue: VecDeque<Queued<F>>,
    rot: T,
    role: Vec<OLEShare<F>>,
}

impl<T, F> Receiver<T, F> {
    /// Creates a new ROLE receiver.
    ///
    /// # Arguments
    ///
    /// * `rot` - Random OT receiver.
    pub fn new(rot: T) -> Self {
        Self {
            id: OLEId::default(),
            alloc: 0,
            pending: 0,
            queue: VecDeque::new(),
            rot,
            role: Vec::new(),
        }
    }

    /// Returns the random OT receiver.
    pub fn rot(&self) -> &T {
        &self.rot
    }

    /// Returns a mutable reference to the random OT receiver.
    pub fn rot_mut(&mut self) -> &mut T {
        &mut self.rot
    }

    /// Returns the random OT receiver.
    pub fn into_inner(self) -> T {
        self.rot
    }
}

impl<T, F> Receiver<T, F>
where
    T: ROTReceiver<bool, F>,
    F: Field,
{
    /// Returns `true` if the receiver wants to receive.
    pub fn wants_recv(&self) -> bool {
        self.alloc > 0
    }

    /// Receives the OLEs.
    pub fn recv(&mut self, msg: SenderMasks<F>) -> Result<(), ReceiverError> {
        let SenderMasks { masks } = msg;

        let count = self.alloc;
        if self.pending > count {
            return Err(ReceiverError(ErrorRepr::InsufficientOle {
                count: self.pending,
                available: count,
            }));
        } else if masks.len() != count {
            return Err(ReceiverError(ErrorRepr::WrongCount {
                expected: count,
                actual: masks.len(),
            }));
        }

        let ROTReceiverOutput {
            choices,
            msgs: corr,
            ..
        } = self
            .rot
            .try_recv_rot(count * F::BIT_SIZE)
            .map_err(ReceiverError::ot)?;

        let shares: Vec<OLEShare<F>> = choices
            .chunks(F::BIT_SIZE)
            .zip(corr.chunks(F::BIT_SIZE))
            .zip(masks)
            .map(|((bits, corr), mask)| {
                OLEShare::new_ole_receiver(
                    bits,
                    Array::<F, F::BitSize>::try_from(corr)
                        .expect("slice should have length of bit size of field element"),
                    mask,
                )
            })
            .collect();

        let mut i = 0;
        for Queued { count, sender } in self.queue.drain(..) {
            let shares = shares[i..i + count].to_vec();
            i += count;

            sender.send(ROLEReceiverOutput {
                id: self.id.next(),
                shares,
            });
        }

        // Store the rest of the ROLEs which were not queued.
        self.role.extend_from_slice(&shares[i..]);
        self.alloc = 0;
        self.pending = 0;

        Ok(())
    }
}

impl<T, F> ROLEReceiver<F> for Receiver<T, F>
where
    T: ROTReceiver<bool, F>,
    F: Field,
{
    type Error = ReceiverError;
    type Future = MaybeDone<ROLEReceiverOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<(), ReceiverError> {
        self.rot
            .alloc(count * F::BIT_SIZE)
            .map_err(ReceiverError::ot)?;

        self.alloc += count;

        Ok(())
    }

    fn available(&self) -> usize {
        self.role.len()
    }

    fn try_recv_role(&mut self, count: usize) -> Result<ROLEReceiverOutput<F>, Self::Error> {
        if count > self.role.len() {
            return Err(ReceiverError(ErrorRepr::InsufficientOle {
                count,
                available: self.role.len(),
            }));
        }

        let shares = self.role.drain(..count).collect();

        Ok(ROLEReceiverOutput {
            id: self.id.next(),
            shares,
        })
    }

    fn queue_recv_role(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        self.pending += count;
        self.queue.push_back(Queued { count, sender });

        Ok(recv)
    }
}

/// Error for [`Receiver`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ReceiverError(#[from] ErrorRepr);

impl ReceiverError {
    fn ot<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Ot(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("ot error: {0}")]
    Ot(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("insufficient OLE, wanted: {count}, available: {available}")]
    InsufficientOle { count: usize, available: usize },
    #[error("sender sent wrong number of OLEs, expected: {expected}, actual: {actual}")]
    WrongCount { expected: usize, actual: usize },
}
