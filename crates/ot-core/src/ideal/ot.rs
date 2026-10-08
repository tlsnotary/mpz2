//! Ideal Chosen-Message Oblivious Transfer functionality.
//!
//! Two implementations are provided:
//!
//! 1. **`IdealOTSender`/`IdealOTReceiver`** (message-based): Separate sender
//!    and receiver types communicating via `FlushMsg`.
//!
//! 2. **`IdealOT`** wrapper: Holds both sender and receiver, provides unified
//!    interface for tests.

use std::{
    mem,
    sync::{Arc, Mutex},
};

use mpz_common::future::{MaybeDone, Output, Sender, new_output};
use mpz_core::Block;
use serde::{Deserialize, Serialize};

use crate::{
    TransferId,
    ot::{OTReceiver, OTReceiverOutput, OTSender, OTSenderOutput},
};

// =============================================================================
// Message-based ideal OT (separate sender/receiver)
// =============================================================================

/// Message sent from sender to receiver during flush.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushMsg {
    /// Queued message batches with their counts.
    pub batches: Vec<FlushBatch>,
}

/// A batch of messages from one queue_send_ot call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushBatch {
    /// Number of messages in this batch.
    pub count: usize,
    /// The messages (pairs of blocks).
    pub msgs: Vec<[Block; 2]>,
}

/// Returns a new ideal OT sender and receiver.
pub fn ideal_ot() -> (IdealOTSender, IdealOTReceiver) {
    (IdealOTSender::new(), IdealOTReceiver::new())
}

/// Ideal OT sender (message-based).
#[derive(Debug, Default)]
pub struct IdealOTSender {
    /// Transfer ID counter.
    transfer_id: TransferId,
    /// Queued message batches.
    batches: Vec<(usize, Vec<[Block; 2]>, Sender<OTSenderOutput>)>,
}

impl IdealOTSender {
    /// Creates a new sender.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the sender wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        !self.batches.is_empty()
    }

    /// Flushes pending operations, returning the message to send to receiver.
    ///
    /// Returns `None` if there's nothing to flush.
    pub fn flush(&mut self) -> Option<FlushMsg> {
        if self.batches.is_empty() {
            return None;
        }

        // Take ownership of batches (no clone)
        let taken = mem::take(&mut self.batches);

        let mut flush_batches = Vec::with_capacity(taken.len());
        for (count, msgs, sender) in taken {
            flush_batches.push(FlushBatch { count, msgs });
            sender.send(OTSenderOutput {
                id: self.transfer_id.next(),
            });
        }

        Some(FlushMsg {
            batches: flush_batches,
        })
    }
}

impl OTSender<Block> for IdealOTSender {
    type Error = IdealOTError;
    type Future = MaybeDone<OTSenderOutput>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        // OT doesn't need pre-allocation
        Ok(())
    }

    fn queue_send_ot(&mut self, msgs: &[[Block; 2]]) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();
        self.batches.push((msgs.len(), msgs.to_vec(), sender));
        Ok(recv)
    }
}

/// Ideal OT receiver (message-based).
#[derive(Debug, Default)]
pub struct IdealOTReceiver {
    /// Transfer ID counter.
    transfer_id: TransferId,
    /// Queued choice batches.
    batches: Vec<(Vec<bool>, Sender<OTReceiverOutput<Block>>)>,
}

impl IdealOTReceiver {
    /// Creates a new receiver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the receiver wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        !self.batches.is_empty()
    }

    /// Flushes pending operations using the message from the sender.
    pub fn flush(&mut self, flush_msg: FlushMsg) -> Result<(), IdealOTError> {
        if flush_msg.batches.len() != self.batches.len() {
            return Err(IdealOTError::new(format!(
                "batch count mismatch: sender={}, receiver={}",
                flush_msg.batches.len(),
                self.batches.len()
            )));
        }

        for (sender_batch, (choices, output_sender)) in flush_msg
            .batches
            .into_iter()
            .zip(mem::take(&mut self.batches))
        {
            if sender_batch.count != choices.len() {
                return Err(IdealOTError::new(format!(
                    "count mismatch: sender={}, receiver={}",
                    sender_batch.count,
                    choices.len()
                )));
            }

            // Compute chosen messages: chosen[i] = msgs[i][choices[i]]
            let chosen: Vec<Block> = sender_batch
                .msgs
                .into_iter()
                .zip(&choices)
                .map(|([zero, one], &choice)| if choice { one } else { zero })
                .collect();

            output_sender.send(OTReceiverOutput {
                id: self.transfer_id.next(),
                msgs: chosen,
            });
        }

        Ok(())
    }
}

impl OTReceiver<bool, Block> for IdealOTReceiver {
    type Error = IdealOTError;
    type Future = MaybeDone<OTReceiverOutput<Block>>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        // OT doesn't need pre-allocation
        Ok(())
    }

    fn queue_recv_ot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();
        self.batches.push((choices.to_vec(), sender));
        Ok(recv)
    }
}

/// Ideal OT error.
#[derive(Debug, thiserror::Error)]
#[error("ideal OT error: {0}")]
pub struct IdealOTError(String);

impl IdealOTError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

// =============================================================================
// IdealOT wrapper for test convenience
// =============================================================================

/// Ideal OT wrapper that holds both sender and receiver.
///
/// This provides a unified interface for tests where both sender and receiver
/// share state. Internally uses the message-based `IdealOTSender` and
/// `IdealOTReceiver`.
#[derive(Debug, Clone, Default)]
pub struct IdealOT {
    inner: Arc<Mutex<IdealOTInner>>,
}

#[derive(Debug, Default)]
struct IdealOTInner {
    sender: IdealOTSender,
    receiver: IdealOTReceiver,
}

impl IdealOT {
    /// Creates a new ideal OT functionality.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the functionality wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.sender.wants_flush() || inner.receiver.wants_flush()
    }

    /// Flushes the functionality.
    ///
    /// Internally passes the flush message from sender to receiver.
    pub fn flush(&mut self) -> Result<(), IdealOTError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(msg) = inner.sender.flush() {
            inner.receiver.flush(msg)?;
        }
        Ok(())
    }

    /// Executes chosen-message oblivious transfers.
    pub fn transfer(
        &mut self,
        choices: &[bool],
        msgs: &[[Block; 2]],
    ) -> Result<(OTSenderOutput, OTReceiverOutput<Block>), IdealOTError> {
        let mut sender_output = self.queue_send_ot(msgs)?;
        let mut receiver_output = self.queue_recv_ot(choices)?;

        self.flush()?;

        Ok((
            sender_output.try_recv().unwrap().unwrap(),
            receiver_output.try_recv().unwrap().unwrap(),
        ))
    }
}

impl OTSender<Block> for IdealOT {
    type Error = IdealOTError;
    type Future = MaybeDone<OTSenderOutput>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn queue_send_ot(&mut self, msgs: &[[Block; 2]]) -> Result<Self::Future, Self::Error> {
        self.inner.lock().unwrap().sender.queue_send_ot(msgs)
    }
}

impl OTReceiver<bool, Block> for IdealOT {
    type Error = IdealOTError;
    type Future = MaybeDone<OTReceiverOutput<Block>>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn queue_recv_ot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        self.inner.lock().unwrap().receiver.queue_recv_ot(choices)
    }
}

#[cfg(test)]
mod tests {
    use mpz_core::Block;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use crate::test::assert_ot;

    use super::*;

    /// Test using separate sender/receiver with explicit message passing.
    #[test]
    fn test_ideal_ot_separate() {
        let mut rng = StdRng::seed_from_u64(0);
        let choices: Vec<bool> = (0..100).map(|_| rng.random()).collect();

        let msgs: Vec<[Block; 2]> = (0..100).map(|_| [rng.random(), rng.random()]).collect();

        let (mut sender, mut receiver) = ideal_ot();

        // Queue operations
        let mut sender_output = sender.queue_send_ot(&msgs).unwrap();
        let mut receiver_output = receiver.queue_recv_ot(&choices).unwrap();

        // Flush (sender produces message, receiver consumes it)
        let flush_msg = sender.flush().expect("should have message");
        receiver.flush(flush_msg).unwrap();

        // Get outputs
        let OTSenderOutput { .. } = sender_output.try_recv().unwrap().unwrap();
        let OTReceiverOutput { msgs: chosen, .. } = receiver_output.try_recv().unwrap().unwrap();

        assert_ot(&choices, &msgs, &chosen);
    }

    /// Test using IdealOT wrapper with unified interface.
    #[test]
    fn test_ideal_ot_wrapper() {
        let mut rng = StdRng::seed_from_u64(0);
        let choices: Vec<bool> = (0..100).map(|_| rng.random()).collect();

        let msgs: Vec<[Block; 2]> = (0..100).map(|_| [rng.random(), rng.random()]).collect();

        let (OTSenderOutput { .. }, OTReceiverOutput { msgs: chosen, .. }) =
            IdealOT::default().transfer(&choices, &msgs).unwrap();

        assert_ot(&choices, &msgs, &chosen);
    }
}
