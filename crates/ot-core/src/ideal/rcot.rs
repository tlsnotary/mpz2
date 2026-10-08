//! Ideal Random Correlated Oblivious Transfer functionality.
//!
//! This implementation uses message-based communication where the sender
//! produces a `FlushMsg` that the receiver consumes. Keys are generated
//! deterministically via counter addition.

use std::mem;

use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_core::Block;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

use crate::{
    TransferId,
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
};

/// Message sent from sender to receiver during flush.
/// Only contains seed + offset + count + delta, not the actual data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushMsg {
    /// Base seed for key generation.
    pub seed: Block,
    /// Offset into the key sequence.
    pub offset: u64,
    /// Number of OTs to generate.
    pub count: usize,
    /// Global correlation delta.
    pub delta: Block,
}

/// Generate keys via simple counter addition: key[i] = seed + offset + i
#[inline]
fn generate_keys(seed: Block, offset: u64, count: usize) -> Vec<Block> {
    let base = u128::from_le_bytes(seed.to_bytes());
    (0..count)
        .map(|i| {
            let val = base.wrapping_add(offset as u128).wrapping_add(i as u128);
            Block::from(val.to_le_bytes())
        })
        .collect()
}

/// Returns a new ideal RCOT sender and receiver.
///
/// This implementation sends only a seed during flush, and the receiver
/// regenerates keys locally via counter addition.
pub fn ideal_rcot(seed: Block, delta: Block) -> (IdealRCOTSender, IdealRCOTReceiver) {
    (IdealRCOTSender::new(seed, delta), IdealRCOTReceiver::new())
}

/// Ideal RCOT sender.
///
/// Sends only seed + offset + count + delta, not the actual keys/msgs.
#[derive(Debug)]
pub struct IdealRCOTSender {
    delta: Block,
    seed: Block,
    /// Current offset into key sequence.
    offset: u64,
    /// Pending allocation count.
    pending: usize,
    /// Generated keys (sender's OT outputs).
    keys: Vec<Block>,
    /// Queue of (count, sender) for deferred output.
    queue: Vec<(usize, Sender<RCOTSenderOutput<Block>>)>,
    /// Transfer ID counter.
    transfer_id: TransferId,
}

impl IdealRCOTSender {
    /// Creates a new sender with the given seed and delta.
    pub fn new(seed: Block, delta: Block) -> Self {
        Self {
            delta,
            seed,
            offset: 0,
            pending: 0,
            keys: Vec::new(),
            queue: Vec::new(),
            transfer_id: TransferId::default(),
        }
    }

    /// Returns `true` if the sender wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        self.pending > 0 || !self.queue.is_empty()
    }

    /// Flushes pending operations, returning the message to send to receiver.
    ///
    /// Returns `None` if there's nothing to flush.
    pub fn flush(&mut self) -> Option<FlushMsg> {
        if self.pending == 0 && self.queue.is_empty() {
            return None;
        }

        let count = self.pending;
        let current_offset = self.offset;

        if count > 0 {
            // Generate keys via counter addition
            let keys = generate_keys(self.seed, current_offset, count);

            // Store keys for sender
            self.keys.extend(keys);

            // Advance offset
            self.offset += count as u64;

            self.pending = 0;

            // Fulfill queued requests
            for (count, sender) in mem::take(&mut self.queue) {
                let keys_len = self.keys.len();
                let keys = self.keys.split_off(keys_len - count);
                sender.send(RCOTSenderOutput {
                    id: self.transfer_id.next(),
                    keys,
                });
            }

            Some(FlushMsg {
                seed: self.seed,
                offset: current_offset,
                count,
                delta: self.delta,
            })
        } else {
            // Only queued requests, no new allocations
            for (count, sender) in mem::take(&mut self.queue) {
                let keys_len = self.keys.len();
                let keys = self.keys.split_off(keys_len - count);
                sender.send(RCOTSenderOutput {
                    id: self.transfer_id.next(),
                    keys,
                });
            }
            None
        }
    }
}

impl RCOTSender<Block> for IdealRCOTSender {
    type Error = IdealRCOTError;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.pending += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.keys.len()
    }

    fn delta(&self) -> Block {
        self.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        if count > self.keys.len() {
            return Err(IdealRCOTError::new(format!(
                "not enough OTs: available={}, requested={}",
                self.keys.len(),
                count
            )));
        }

        let keys_len = self.keys.len();
        let keys = self.keys.split_off(keys_len - count);

        Ok(RCOTSenderOutput {
            id: self.transfer_id.next(),
            keys,
        })
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (send, recv) = new_output();

        // If enough keys available, send immediately
        if self.keys.len() >= count {
            let keys_len = self.keys.len();
            let keys = self.keys.split_off(keys_len - count);
            send.send(RCOTSenderOutput {
                id: self.transfer_id.next(),
                keys,
            });
        } else {
            // Otherwise queue for flush() to fulfill
            self.queue.push((count, send));
        }

        Ok(recv)
    }
}

/// Ideal RCOT receiver.
///
/// Regenerates keys locally from the received seed via counter addition.
#[derive(Debug)]
pub struct IdealRCOTReceiver {
    /// RNG for generating choices (seeded for determinism).
    rng: ChaCha8Rng,
    /// Pending allocation count.
    pending: usize,
    /// Received choice bits.
    choices: Vec<bool>,
    /// Received messages.
    msgs: Vec<Block>,
    /// Queue of (count, sender) for deferred output.
    queue: Vec<(usize, Sender<RCOTReceiverOutput<bool, Block>>)>,
    /// Transfer ID counter.
    transfer_id: TransferId,
    /// Cached delta from flush message.
    delta: Option<Block>,
}

impl IdealRCOTReceiver {
    /// Creates a new receiver with a fixed seed for deterministic behavior.
    pub fn new() -> Self {
        Self::from_seed(0)
    }

    /// Creates a new receiver with the given seed.
    pub fn from_seed(seed: u64) -> Self {
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed),
            pending: 0,
            choices: Vec::new(),
            msgs: Vec::new(),
            queue: Vec::new(),
            transfer_id: TransferId::default(),
            delta: None,
        }
    }

    /// Returns `true` if the receiver wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        self.pending > 0 || !self.queue.is_empty()
    }

    /// Flushes pending operations using the message from the sender.
    pub fn flush(&mut self, flush_msg: FlushMsg) -> Result<(), IdealRCOTError> {
        if flush_msg.count != self.pending {
            return Err(IdealRCOTError::new(format!(
                "count mismatch: expected={}, received={}",
                self.pending, flush_msg.count
            )));
        }

        // Cache delta
        self.delta = Some(flush_msg.delta);

        // Regenerate keys via counter addition (same as sender)
        let keys = generate_keys(flush_msg.seed, flush_msg.offset, flush_msg.count);

        // Generate random choices via seeded RNG
        let choices: Vec<bool> = (0..flush_msg.count).map(|_| self.rng.random()).collect();

        // Compute receiver's messages: msg_i = key_i XOR (choice_i * delta)
        let msgs: Vec<Block> = keys
            .iter()
            .zip(&choices)
            .map(
                |(key, &choice)| {
                    if choice { *key ^ flush_msg.delta } else { *key }
                },
            )
            .collect();

        // Store received data
        self.choices.extend(choices);
        self.msgs.extend(msgs);

        self.pending = 0;

        // Fulfill queued requests
        for (count, sender) in mem::take(&mut self.queue) {
            let len = self.choices.len();
            let choices = self.choices.split_off(len - count);
            let msgs = self.msgs.split_off(len - count);
            sender.send(RCOTReceiverOutput {
                id: self.transfer_id.next(),
                choices,
                msgs,
            });
        }

        Ok(())
    }
}

impl Default for IdealRCOTReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl RCOTReceiver<bool, Block> for IdealRCOTReceiver {
    type Error = IdealRCOTError;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.pending += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.choices.len()
    }

    fn try_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        if count > self.choices.len() {
            return Err(IdealRCOTError::new(format!(
                "not enough OTs: available={}, requested={}",
                self.choices.len(),
                count
            )));
        }

        let len = self.choices.len();
        let choices = self.choices.split_off(len - count);
        let msgs = self.msgs.split_off(len - count);

        Ok(RCOTReceiverOutput {
            id: self.transfer_id.next(),
            choices,
            msgs,
        })
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (send, recv) = new_output();

        // If enough available, send immediately
        if self.choices.len() >= count {
            let len = self.choices.len();
            let choices = self.choices.split_off(len - count);
            let msgs = self.msgs.split_off(len - count);
            send.send(RCOTReceiverOutput {
                id: self.transfer_id.next(),
                choices,
                msgs,
            });
        } else {
            // Otherwise queue for flush() to fulfill
            self.queue.push((count, send));
        }

        Ok(recv)
    }
}

/// Ideal RCOT error.
#[derive(Debug, thiserror::Error)]
#[error("ideal RCOT error: {0}")]
pub struct IdealRCOTError(String);

impl IdealRCOTError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

// =============================================================================
// IdealRCOT wrapper for test convenience
// =============================================================================

use std::sync::{Arc, Mutex};

/// Ideal RCOT wrapper that holds both sender and receiver.
///
/// This provides a unified interface for tests where both sender and receiver
/// share state. Internally uses the message-based `IdealRCOTSender` and
/// `IdealRCOTReceiver`.
#[derive(Debug, Clone)]
pub struct IdealRCOT {
    inner: Arc<Mutex<IdealRCOTInner>>,
}

#[derive(Debug)]
struct IdealRCOTInner {
    sender: IdealRCOTSender,
    receiver: IdealRCOTReceiver,
}

impl IdealRCOT {
    /// Creates a new ideal RCOT.
    pub fn new(seed: Block, delta: Block) -> Self {
        let (sender, receiver) = ideal_rcot(seed, delta);
        Self {
            inner: Arc::new(Mutex::new(IdealRCOTInner { sender, receiver })),
        }
    }

    /// Allocates `count` random correlated OTs for both sender and receiver.
    pub fn alloc(&mut self, count: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.sender.alloc(count).unwrap();
        inner.receiver.alloc(count).unwrap();
    }

    /// Flushes pending operations.
    ///
    /// Internally passes the flush message from sender to receiver.
    pub fn flush(&mut self) -> Result<(), IdealRCOTError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(msg) = inner.sender.flush() {
            inner.receiver.flush(msg)?;
        }
        Ok(())
    }

    /// Transfers `count` random correlated OTs.
    pub fn transfer(
        &mut self,
        count: usize,
    ) -> Result<(RCOTSenderOutput<Block>, RCOTReceiverOutput<bool, Block>), IdealRCOTError> {
        let mut inner = self.inner.lock().unwrap();
        let sender_out = inner.sender.try_send_rcot(count)?;
        let receiver_out = inner.receiver.try_recv_rcot(count)?;
        Ok((sender_out, receiver_out))
    }

    /// Returns the delta value.
    pub fn delta(&self) -> Block {
        self.inner.lock().unwrap().sender.delta
    }
}

impl RCOTSender<Block> for IdealRCOT {
    type Error = IdealRCOTError;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        let mut inner = self.inner.lock().unwrap();
        inner.sender.alloc(count)?;
        inner.receiver.alloc(count)?;
        Ok(())
    }

    fn available(&self) -> usize {
        self.inner.lock().unwrap().sender.available()
    }

    fn delta(&self) -> Block {
        self.inner.lock().unwrap().sender.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        self.inner.lock().unwrap().sender.try_send_rcot(count)
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.inner.lock().unwrap().sender.queue_send_rcot(count)
    }
}

impl RCOTReceiver<bool, Block> for IdealRCOT {
    type Error = IdealRCOTError;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        let mut inner = self.inner.lock().unwrap();
        inner.sender.alloc(count)?;
        inner.receiver.alloc(count)?;
        Ok(())
    }

    fn available(&self) -> usize {
        self.inner.lock().unwrap().receiver.available()
    }

    fn try_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        self.inner.lock().unwrap().receiver.try_recv_rcot(count)
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.inner.lock().unwrap().receiver.queue_recv_rcot(count)
    }
}

impl Default for IdealRCOT {
    fn default() -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        Self::new(rng.random(), rng.random())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test::assert_cot;

    /// Test using separate sender/receiver with explicit message passing.
    #[test]
    fn test_ideal_rcot_separate() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let seed: Block = rng.random();
        let delta: Block = rng.random();

        let (mut sender, mut receiver) = ideal_rcot(seed, delta);

        const COUNT: usize = 128;

        // Allocate
        sender.alloc(COUNT).unwrap();
        receiver.alloc(COUNT).unwrap();

        // Flush (sender produces message, receiver consumes it)
        let flush_msg = sender.flush().expect("should have message");
        receiver.flush(flush_msg).unwrap();

        // Transfer
        let sender_out = sender.try_send_rcot(COUNT).unwrap();
        let receiver_out = receiver.try_recv_rcot(COUNT).unwrap();

        // Verify correctness
        assert_cot(
            delta,
            &receiver_out.choices,
            &sender_out.keys,
            &receiver_out.msgs,
        );
    }

    /// Test using IdealRCOT wrapper with unified interface.
    #[test]
    fn test_ideal_rcot_wrapper() {
        let mut ideal = IdealRCOT::default();

        ideal.alloc(100);
        ideal.flush().unwrap();

        let (RCOTSenderOutput { keys, .. }, RCOTReceiverOutput { choices, msgs, .. }) =
            ideal.transfer(100).unwrap();

        assert_cot(ideal.delta(), &choices, &keys, &msgs);
    }
}
