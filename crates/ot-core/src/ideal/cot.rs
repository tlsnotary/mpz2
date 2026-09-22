//! Ideal Correlated Oblivious Transfer functionality.
//!
//! Two implementations are provided:
//!
//! 1. **`IdealCOTSender`/`IdealCOTReceiver`** (message-based): Separate sender
//!    and receiver types communicating via `FlushMsg`.
//!
//! 2. **`IdealCOT`** wrapper: Holds both sender and receiver, provides unified
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
    cot::{COTReceiver, COTReceiverOutput, COTSender, COTSenderOutput},
};

// =============================================================================
// Message-based ideal COT (separate sender/receiver)
// =============================================================================

/// Message sent from sender to receiver during flush.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushMsg {
    /// Global correlation key.
    pub delta: Block,
    /// Queued key batches with their counts.
    pub batches: Vec<FlushBatch>,
}

/// A batch of keys from one queue_send_cot call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushBatch {
    /// Number of keys in this batch.
    pub count: usize,
    /// The keys.
    pub keys: Vec<Block>,
}

/// Returns a new ideal COT sender and receiver.
pub fn ideal_cot(delta: Block) -> (IdealCOTSender, IdealCOTReceiver) {
    (IdealCOTSender::new(delta), IdealCOTReceiver::new())
}

/// Ideal COT sender (message-based).
#[derive(Debug)]
pub struct IdealCOTSender {
    /// Global correlation key.
    delta: Block,
    /// Transfer ID counter.
    transfer_id: TransferId,
    /// Queued key batches.
    batches: Vec<(usize, Vec<Block>, Sender<COTSenderOutput>)>,
}

impl IdealCOTSender {
    /// Creates a new sender with the given delta.
    pub fn new(delta: Block) -> Self {
        Self {
            delta,
            transfer_id: TransferId::default(),
            batches: Vec::new(),
        }
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
        for (count, keys, sender) in taken {
            flush_batches.push(FlushBatch { count, keys });
            sender.send(COTSenderOutput {
                id: self.transfer_id.next(),
            });
        }

        Some(FlushMsg {
            delta: self.delta,
            batches: flush_batches,
        })
    }
}

impl COTSender<Block> for IdealCOTSender {
    type Error = IdealCOTError;
    type Future = MaybeDone<COTSenderOutput>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        // COT doesn't need pre-allocation in ideal functionality
        Ok(())
    }

    fn available(&self) -> usize {
        self.batches.iter().map(|(count, _, _)| count).sum()
    }

    fn delta(&self) -> Block {
        self.delta
    }

    fn queue_send_cot(&mut self, keys: &[Block]) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();
        self.batches.push((keys.len(), keys.to_vec(), sender));
        Ok(recv)
    }
}

/// Ideal COT receiver (message-based).
#[derive(Debug, Default)]
pub struct IdealCOTReceiver {
    /// Transfer ID counter.
    transfer_id: TransferId,
    /// Queued choice batches.
    batches: Vec<(Vec<bool>, Sender<COTReceiverOutput<Block>>)>,
}

impl IdealCOTReceiver {
    /// Creates a new receiver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the receiver wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        !self.batches.is_empty()
    }

    /// Flushes pending operations using the message from the sender.
    pub fn flush(&mut self, flush_msg: FlushMsg) -> Result<(), IdealCOTError> {
        if flush_msg.batches.len() != self.batches.len() {
            return Err(IdealCOTError::new(format!(
                "batch count mismatch: sender={}, receiver={}",
                flush_msg.batches.len(),
                self.batches.len()
            )));
        }

        let delta = flush_msg.delta;

        for (sender_batch, (choices, output_sender)) in flush_msg
            .batches
            .into_iter()
            .zip(mem::take(&mut self.batches))
        {
            if sender_batch.count != choices.len() {
                return Err(IdealCOTError::new(format!(
                    "count mismatch: sender={}, receiver={}",
                    sender_batch.count,
                    choices.len()
                )));
            }

            // Compute correlated messages: msg[i] = if choice { key ^ delta }
            // else { key }
            let msgs: Vec<Block> = sender_batch
                .keys
                .into_iter()
                .zip(&choices)
                .map(|(key, &choice)| if choice { key ^ delta } else { key })
                .collect();

            output_sender.send(COTReceiverOutput {
                id: self.transfer_id.next(),
                msgs,
            });
        }

        Ok(())
    }
}

impl COTReceiver<bool, Block> for IdealCOTReceiver {
    type Error = IdealCOTError;
    type Future = MaybeDone<COTReceiverOutput<Block>>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        // COT doesn't need pre-allocation in ideal functionality
        Ok(())
    }

    fn available(&self) -> usize {
        self.batches.iter().map(|(choices, _)| choices.len()).sum()
    }

    fn queue_recv_cot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();
        self.batches.push((choices.to_vec(), sender));
        Ok(recv)
    }
}

/// Ideal COT error.
#[derive(Debug, thiserror::Error)]
#[error("ideal COT error: {0}")]
pub struct IdealCOTError(String);

impl IdealCOTError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

// =============================================================================
// IdealCOT wrapper for test convenience
// =============================================================================

/// Ideal COT wrapper that holds both sender and receiver.
///
/// This provides a unified interface for tests where both sender and receiver
/// share state. Internally uses the message-based `IdealCOTSender` and
/// `IdealCOTReceiver`.
#[derive(Debug, Clone)]
pub struct IdealCOT {
    inner: Arc<Mutex<IdealCOTInner>>,
}

#[derive(Debug)]
struct IdealCOTInner {
    sender: IdealCOTSender,
    receiver: IdealCOTReceiver,
}

impl IdealCOT {
    /// Creates a new ideal COT functionality.
    ///
    /// # Arguments
    ///
    /// * `delta` - Global correlation key.
    pub fn new(delta: Block) -> Self {
        Self {
            inner: Arc::new(Mutex::new(IdealCOTInner {
                sender: IdealCOTSender::new(delta),
                receiver: IdealCOTReceiver::new(),
            })),
        }
    }

    /// Returns `true` if the functionality wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.sender.wants_flush() || inner.receiver.wants_flush()
    }

    /// Flushes the functionality.
    ///
    /// Internally passes the flush message from sender to receiver.
    pub fn flush(&mut self) -> Result<(), IdealCOTError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(msg) = inner.sender.flush() {
            inner.receiver.flush(msg)?;
        }
        Ok(())
    }

    /// Transfers correlated OTs.
    pub fn transfer(
        &mut self,
        choices: &[bool],
        keys: &[Block],
    ) -> Result<(COTSenderOutput, COTReceiverOutput<Block>), IdealCOTError> {
        let mut sender_output = self.queue_send_cot(keys)?;
        let mut receiver_output = self.queue_recv_cot(choices)?;

        self.flush()?;

        Ok((
            sender_output.try_recv().unwrap().unwrap(),
            receiver_output.try_recv().unwrap().unwrap(),
        ))
    }
}

impl COTSender<Block> for IdealCOT {
    type Error = IdealCOTError;
    type Future = MaybeDone<COTSenderOutput>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn available(&self) -> usize {
        self.inner.lock().unwrap().sender.available()
    }

    fn delta(&self) -> Block {
        self.inner.lock().unwrap().sender.delta()
    }

    fn queue_send_cot(&mut self, keys: &[Block]) -> Result<Self::Future, Self::Error> {
        self.inner.lock().unwrap().sender.queue_send_cot(keys)
    }
}

impl COTReceiver<bool, Block> for IdealCOT {
    type Error = IdealCOTError;
    type Future = MaybeDone<COTReceiverOutput<Block>>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn available(&self) -> usize {
        self.inner.lock().unwrap().receiver.available()
    }

    fn queue_recv_cot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        self.inner.lock().unwrap().receiver.queue_recv_cot(choices)
    }
}

#[cfg(test)]
mod tests {
    use mpz_core::Block;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use crate::test::assert_cot;

    use super::*;

    /// Test using separate sender/receiver with explicit message passing.
    #[test]
    fn test_ideal_cot_separate() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Block::random(&mut rng);

        let count = 128;
        let choices: Vec<bool> = (0..count).map(|_| rng.random()).collect();
        let keys: Vec<Block> = (0..count).map(|_| rng.random()).collect();

        let (mut sender, mut receiver) = ideal_cot(delta);

        // Queue operations
        let mut sender_output = sender.queue_send_cot(&keys).unwrap();
        let mut receiver_output = receiver.queue_recv_cot(&choices).unwrap();

        // Flush (sender produces message, receiver consumes it)
        let flush_msg = sender.flush().expect("should have message");
        receiver.flush(flush_msg).unwrap();

        // Get outputs
        let COTSenderOutput { id: sender_id } = sender_output.try_recv().unwrap().unwrap();
        let COTReceiverOutput {
            id: receiver_id,
            msgs: received,
        } = receiver_output.try_recv().unwrap().unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_cot(delta, &choices, &keys, &received);
    }

    /// Test using IdealCOT wrapper with unified interface.
    #[test]
    fn test_ideal_cot_wrapper() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Block::random(&mut rng);

        let count = 128;
        let choices: Vec<bool> = (0..count).map(|_| rng.random()).collect();
        let keys: Vec<Block> = (0..count).map(|_| rng.random()).collect();

        let (
            COTSenderOutput { id: sender_id },
            COTReceiverOutput {
                id: receiver_id,
                msgs: received,
            },
        ) = IdealCOT::new(delta).transfer(&choices, &keys).unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_cot(delta, &choices, &keys, &received);
    }
}
