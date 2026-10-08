//! Ideal Random Oblivious Transfer functionality.
//!
//! Two implementations are provided:
//!
//! 1. **`IdealROTSender`/`IdealROTReceiver`** (message-based): Separate sender
//!    and receiver types communicating via `FlushMsg`. Uses seed-based
//!    generation for efficiency - only seed/offset/count are sent, not actual
//!    data.
//!
//! 2. **`IdealROT`** wrapper: Holds both sender and receiver, provides unified
//!    interface for tests.

use std::{
    mem,
    sync::{Arc, Mutex},
};

use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_core::Block;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

use crate::{
    TransferId,
    rot::{ROTReceiver, ROTReceiverOutput, ROTSender, ROTSenderOutput},
};

// =============================================================================
// Message-based ideal ROT (separate sender/receiver)
// =============================================================================

/// Message sent from sender to receiver during flush.
/// Only contains seed + offset + count, not the actual data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushMsg {
    /// Base seed for key/choice generation.
    pub seed: Block,
    /// Offset into the sequence.
    pub offset: u64,
    /// Number of ROTs to generate.
    pub count: usize,
}

/// Generate key pairs deterministically from seed + offset via counter
/// addition.
///
/// For each index i:
/// - keys[i][0] = seed + (offset + i) * 3
/// - keys[i][1] = seed + (offset + i) * 3 + 1
#[inline]
fn generate_keys(seed: Block, offset: u64, count: usize) -> Vec<[Block; 2]> {
    let base = u128::from_le_bytes(seed.to_bytes());
    (0..count)
        .map(|i| {
            let idx = (offset as u128).wrapping_add(i as u128).wrapping_mul(3);
            let k0 = base.wrapping_add(idx);
            let k1 = base.wrapping_add(idx).wrapping_add(1);
            [Block::from(k0.to_le_bytes()), Block::from(k1.to_le_bytes())]
        })
        .collect()
}

/// Returns a new ideal ROT sender and receiver.
pub fn ideal_rot(seed: Block) -> (IdealROTSender, IdealROTReceiver) {
    (IdealROTSender::new(seed), IdealROTReceiver::new())
}

/// Ideal ROT sender (message-based).
///
/// Sends only seed + offset + count, not the actual keys.
#[derive(Debug)]
pub struct IdealROTSender {
    /// Base seed for generation.
    seed: Block,
    /// Current offset into sequence.
    offset: u64,
    /// Pending allocation count.
    pending: usize,
    /// Generated keys (sender's ROT outputs).
    keys: Vec<[Block; 2]>,
    /// Queue of (count, sender) for deferred output.
    queue: Vec<(usize, Sender<ROTSenderOutput<[Block; 2]>>)>,
    /// Transfer ID counter.
    transfer_id: TransferId,
}

impl IdealROTSender {
    /// Creates a new sender with the given seed.
    pub fn new(seed: Block) -> Self {
        Self {
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
            // Generate keys deterministically
            let keys = generate_keys(self.seed, current_offset, count);
            self.keys.extend(keys);
            self.offset += count as u64;
            self.pending = 0;
        }

        // Fulfill queued requests
        for (req_count, sender) in mem::take(&mut self.queue) {
            let keys = self.keys.drain(..req_count).collect();
            sender.send(ROTSenderOutput {
                id: self.transfer_id.next(),
                keys,
            });
        }

        Some(FlushMsg {
            seed: self.seed,
            offset: current_offset,
            count,
        })
    }
}

impl ROTSender<[Block; 2]> for IdealROTSender {
    type Error = IdealROTError;
    type Future = MaybeDone<ROTSenderOutput<[Block; 2]>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.pending += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.keys.len()
    }

    fn try_send_rot(&mut self, count: usize) -> Result<ROTSenderOutput<[Block; 2]>, Self::Error> {
        if count > self.keys.len() {
            return Err(IdealROTError::new(format!(
                "not enough ROTs available: {} < {}",
                self.keys.len(),
                count
            )));
        }

        let keys = self.keys.drain(..count).collect();
        Ok(ROTSenderOutput {
            id: self.transfer_id.next(),
            keys,
        })
    }

    fn queue_send_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        if self.keys.len() >= count {
            let keys = self.keys.drain(..count).collect();
            sender.send(ROTSenderOutput {
                id: self.transfer_id.next(),
                keys,
            });
        } else {
            self.queue.push((count, sender));
        }

        Ok(recv)
    }
}

/// Ideal ROT receiver (message-based).
///
/// Regenerates keys from the received seed, generates choices from own PRG.
#[derive(Debug)]
pub struct IdealROTReceiver {
    /// RNG for generating choices (constant-seeded).
    rng: ChaCha8Rng,
    /// Pending allocation count.
    pending: usize,
    /// Generated choices.
    choices: Vec<bool>,
    /// Generated messages.
    msgs: Vec<Block>,
    /// Explicit choices to use on the next flush instead of generating them.
    forced_choices: Vec<bool>,
    /// Queue of (count, sender) for deferred output.
    queue: Vec<(usize, Sender<ROTReceiverOutput<bool, Block>>)>,
    /// Transfer ID counter.
    transfer_id: TransferId,
}

impl IdealROTReceiver {
    /// Creates a new receiver with constant-seeded RNG for choices.
    pub fn new() -> Self {
        Self {
            rng: ChaCha8Rng::seed_from_u64(0),
            pending: 0,
            choices: Vec::new(),
            msgs: Vec::new(),
            forced_choices: Vec::new(),
            queue: Vec::new(),
            transfer_id: TransferId::default(),
        }
    }

    /// Sets the choices to use on the next flush instead of generating them.
    ///
    /// The length must match the number of ROTs flushed.
    pub fn set_choices(&mut self, choices: Vec<bool>) {
        self.forced_choices = choices;
    }

    /// Returns `true` if the receiver wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        self.pending > 0 || !self.queue.is_empty()
    }

    /// Flushes pending operations using the message from the sender.
    pub fn flush(&mut self, flush_msg: FlushMsg) -> Result<(), IdealROTError> {
        if flush_msg.count != self.pending {
            return Err(IdealROTError::new(format!(
                "count mismatch: sender={}, receiver={}",
                flush_msg.count, self.pending
            )));
        }

        if flush_msg.count > 0 {
            // Regenerate keys from sender's seed (same as sender)
            let keys = generate_keys(flush_msg.seed, flush_msg.offset, flush_msg.count);

            // Use explicit choices if provided, otherwise generate them.
            let choices: Vec<bool> = if self.forced_choices.is_empty() {
                (0..flush_msg.count).map(|_| self.rng.random()).collect()
            } else if self.forced_choices.len() == flush_msg.count {
                mem::take(&mut self.forced_choices)
            } else {
                return Err(IdealROTError::new(format!(
                    "forced choices length mismatch: {} != {}",
                    self.forced_choices.len(),
                    flush_msg.count
                )));
            };

            // Compute receiver's messages: msg_i = keys_i[choice_i]
            let msgs: Vec<Block> = keys
                .iter()
                .zip(&choices)
                .map(|(keys, &choice)| keys[choice as usize])
                .collect();

            self.choices.extend(choices);
            self.msgs.extend(msgs);
            self.pending = 0;
        }

        // Fulfill queued requests
        for (req_count, sender) in mem::take(&mut self.queue) {
            let choices = self.choices.drain(..req_count).collect();
            let msgs = self.msgs.drain(..req_count).collect();
            sender.send(ROTReceiverOutput {
                id: self.transfer_id.next(),
                choices,
                msgs,
            });
        }

        Ok(())
    }
}

impl Default for IdealROTReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl ROTReceiver<bool, Block> for IdealROTReceiver {
    type Error = IdealROTError;
    type Future = MaybeDone<ROTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.pending += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.choices.len()
    }

    fn try_recv_rot(
        &mut self,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, Block>, Self::Error> {
        if count > self.choices.len() {
            return Err(IdealROTError::new(format!(
                "not enough ROTs available: {} < {}",
                self.choices.len(),
                count
            )));
        }

        let choices = self.choices.drain(..count).collect();
        let msgs = self.msgs.drain(..count).collect();
        Ok(ROTReceiverOutput {
            id: self.transfer_id.next(),
            choices,
            msgs,
        })
    }

    fn queue_recv_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        if self.choices.len() >= count {
            let choices = self.choices.drain(..count).collect();
            let msgs = self.msgs.drain(..count).collect();
            sender.send(ROTReceiverOutput {
                id: self.transfer_id.next(),
                choices,
                msgs,
            });
        } else {
            self.queue.push((count, sender));
        }

        Ok(recv)
    }
}

/// Ideal ROT error.
#[derive(Debug, thiserror::Error)]
#[error("ideal ROT error: {0}")]
pub struct IdealROTError(String);

impl IdealROTError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

// =============================================================================
// IdealROT wrapper for test convenience
// =============================================================================

/// Ideal ROT wrapper that holds both sender and receiver.
///
/// This provides a unified interface for tests where both sender and receiver
/// share state. Internally uses the message-based `IdealROTSender` and
/// `IdealROTReceiver`.
#[derive(Debug)]
pub struct IdealROT {
    inner: Arc<Mutex<IdealROTInner>>,
}

#[derive(Debug)]
struct IdealROTInner {
    sender: IdealROTSender,
    receiver: IdealROTReceiver,
}

impl IdealROT {
    /// Creates a new ideal ROT functionality.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed for the PRG.
    pub fn new(seed: Block) -> Self {
        Self {
            inner: Arc::new(Mutex::new(IdealROTInner {
                sender: IdealROTSender::new(seed),
                receiver: IdealROTReceiver::new(),
            })),
        }
    }

    /// Sets the choices the receiver uses on the next flush instead of
    /// generating them.
    ///
    /// The length must match the number of ROTs flushed.
    pub fn set_receiver_choices(&mut self, choices: Vec<bool>) {
        self.inner.lock().unwrap().receiver.set_choices(choices);
    }

    /// Returns `count` random ROTs.
    #[allow(clippy::type_complexity)]
    pub fn transfer(
        &mut self,
        count: usize,
    ) -> Result<(ROTSenderOutput<[Block; 2]>, ROTReceiverOutput<bool, Block>), IdealROTError> {
        ROTSender::alloc(self, count)?;
        ROTReceiver::alloc(self, count)?;
        self.flush()?;
        Ok((self.try_send_rot(count)?, self.try_recv_rot(count)?))
    }

    /// Returns `true` if the functionality wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.sender.wants_flush() || inner.receiver.wants_flush()
    }

    /// Flushes the functionality.
    ///
    /// Internally passes the flush message from sender to receiver.
    pub fn flush(&mut self) -> Result<(), IdealROTError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(msg) = inner.sender.flush() {
            inner.receiver.flush(msg)?;
        }
        Ok(())
    }
}

impl Clone for IdealROT {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Default for IdealROT {
    fn default() -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        Self::new(rng.random())
    }
}

impl ROTSender<[Block; 2]> for IdealROT {
    type Error = IdealROTError;
    type Future = MaybeDone<ROTSenderOutput<[Block; 2]>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.inner.lock().unwrap().sender.alloc(count)
    }

    fn available(&self) -> usize {
        self.inner.lock().unwrap().sender.available()
    }

    fn try_send_rot(&mut self, count: usize) -> Result<ROTSenderOutput<[Block; 2]>, Self::Error> {
        self.inner.lock().unwrap().sender.try_send_rot(count)
    }

    fn queue_send_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.inner.lock().unwrap().sender.queue_send_rot(count)
    }
}

impl ROTReceiver<bool, Block> for IdealROT {
    type Error = IdealROTError;
    type Future = MaybeDone<ROTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.inner.lock().unwrap().receiver.alloc(count)
    }

    fn available(&self) -> usize {
        self.inner.lock().unwrap().receiver.available()
    }

    fn try_recv_rot(
        &mut self,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, Block>, Self::Error> {
        self.inner.lock().unwrap().receiver.try_recv_rot(count)
    }

    fn queue_recv_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.inner.lock().unwrap().receiver.queue_recv_rot(count)
    }
}

#[cfg(test)]
mod tests {
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use crate::test::assert_rot;

    use super::*;

    /// Test using separate sender/receiver with explicit message passing.
    #[test]
    fn test_ideal_rot_separate() {
        let mut rng = StdRng::seed_from_u64(0);
        let seed: Block = rng.random();

        let (mut sender, mut receiver) = ideal_rot(seed);

        let count = 128;

        // Allocate
        ROTSender::alloc(&mut sender, count).unwrap();
        ROTReceiver::alloc(&mut receiver, count).unwrap();

        // Flush (sender produces message, receiver consumes it)
        let flush_msg = sender.flush().expect("should have message");
        receiver.flush(flush_msg).unwrap();

        // Transfer
        let ROTSenderOutput {
            id: sender_id,
            keys,
        } = sender.try_send_rot(count).unwrap();
        let ROTReceiverOutput {
            id: receiver_id,
            choices,
            msgs,
        } = receiver.try_recv_rot(count).unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_rot(&choices, &keys, &msgs);
    }

    /// Test using IdealROT wrapper with unified interface.
    #[test]
    fn test_ideal_rot_wrapper() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut ideal = IdealROT::new(rng.random());

        let count = 128;

        let (
            ROTSenderOutput {
                id: sender_id,
                keys,
            },
            ROTReceiverOutput {
                id: receiver_id,
                choices,
                msgs,
            },
        ) = ideal.transfer(count).unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_rot(&choices, &keys, &msgs);
    }
}
