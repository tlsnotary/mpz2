//! A seeded RCOT mirroring emp-ot's seeded-bootstrap hook.
//!
//! emp-ot's `SeededFerret` (see emp-ot `tools/dump_ferret_golden.cpp`) fills
//! the base COTs from a public seed:
//!
//! * `key_i`   = block `i` of `Prg(seed)`, with bit 0 cleared,
//! * `choice_i` = bit `i` of `Prg(seed ^ 1)` (LSB-first), and
//! * `msg_i`   = `key_i ^ (choice_i ? Δ : 0)`.
//!
//! This is the Rust mirror of that derivation. Both parties derive the key
//! stream locally from the shared (public) seed, so no key material needs to be
//! transmitted — the base lines up given the same `seed` and `Δ`.

use std::sync::{Arc, Mutex};

use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_core::{Block, prg::Prg};
use rand::{Rng, SeedableRng};

use crate::{
    TransferId,
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
};

/// emp's choice-seed: `seed ^ makeBlock(0, 1)`.
fn choice_seed(seed: Block) -> Block {
    let mut bytes = seed.to_bytes();
    bytes[0] ^= 1;
    Block::from(bytes)
}

/// `Prg(seed)` blocks from `offset`, each with bit 0 cleared.
fn keys_at(seed: Block, offset: u64, count: usize) -> Vec<Block> {
    let mut prg = Prg::from_seed(seed);
    let blocks = offset as usize + count;
    let mut buf = vec![0u8; blocks * 16];
    prg.fill_bytes(&mut buf);
    (0..count)
        .map(|i| {
            let start = (offset as usize + i) * 16;
            let mut key = [0u8; 16];
            key.copy_from_slice(&buf[start..start + 16]);
            key[0] &= 0xFE;
            Block::from(key)
        })
        .collect()
}

/// `Prg(seed ^ 1)` bits from `offset`, LSB-first (8 bits per byte).
fn choices_at(seed: Block, offset: u64, count: usize) -> Vec<bool> {
    let mut prg = Prg::from_seed(choice_seed(seed));
    let end = offset + count as u64;
    let mut buf = vec![0u8; end.div_ceil(8) as usize];
    prg.fill_bytes(&mut buf);
    (0..count)
        .map(|i| {
            let bit = offset + i as u64;
            (buf[(bit / 8) as usize] >> (bit % 8)) & 1 == 1
        })
        .collect()
}

/// Returns a new emp-mirror RCOT sender and receiver.
pub fn emp_rcot(seed: Block, delta: Block) -> (EmpRCOTSender, EmpRCOTReceiver) {
    (
        EmpRCOTSender::new(seed, delta),
        EmpRCOTReceiver::new(seed, delta),
    )
}

/// emp-mirror RCOT sender.
#[derive(Debug)]
pub struct EmpRCOTSender {
    seed: Block,
    delta: Block,
    offset: u64,
    pending: usize,
    keys: Vec<Block>,
    queue: Vec<(usize, Sender<RCOTSenderOutput<Block>>)>,
    transfer_id: TransferId,
}

impl EmpRCOTSender {
    /// Creates a new sender.
    pub fn new(seed: Block, delta: Block) -> Self {
        Self {
            seed,
            delta,
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

    /// Materializes any pending correlations.
    pub fn flush(&mut self) {
        if self.pending == 0 {
            return;
        }
        self.keys
            .extend(keys_at(self.seed, self.offset, self.pending));
        self.offset += self.pending as u64;
        self.pending = 0;
        for (count, sender) in std::mem::take(&mut self.queue) {
            let len = self.keys.len();
            let keys = self.keys.split_off(len - count);
            sender.send(RCOTSenderOutput {
                id: self.transfer_id.next(),
                keys,
            });
        }
    }
}

impl RCOTSender<Block> for EmpRCOTSender {
    type Error = EmpRCOTError;
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
            return Err(EmpRCOTError(format!(
                "not enough OTs: available={}, requested={count}",
                self.keys.len()
            )));
        }
        let len = self.keys.len();
        let keys = self.keys.split_off(len - count);
        Ok(RCOTSenderOutput {
            id: self.transfer_id.next(),
            keys,
        })
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (send, recv) = new_output();
        if self.keys.len() >= count {
            let len = self.keys.len();
            let keys = self.keys.split_off(len - count);
            send.send(RCOTSenderOutput {
                id: self.transfer_id.next(),
                keys,
            });
        } else {
            self.queue.push((count, send));
        }
        Ok(recv)
    }
}

/// emp-mirror RCOT receiver.
#[derive(Debug)]
pub struct EmpRCOTReceiver {
    seed: Block,
    delta: Block,
    offset: u64,
    pending: usize,
    choices: Vec<bool>,
    msgs: Vec<Block>,
    queue: Vec<(usize, Sender<RCOTReceiverOutput<bool, Block>>)>,
    transfer_id: TransferId,
}

impl EmpRCOTReceiver {
    /// Creates a new receiver.
    pub fn new(seed: Block, delta: Block) -> Self {
        Self {
            seed,
            delta,
            offset: 0,
            pending: 0,
            choices: Vec::new(),
            msgs: Vec::new(),
            queue: Vec::new(),
            transfer_id: TransferId::default(),
        }
    }

    /// Returns `true` if the receiver wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        self.pending > 0 || !self.queue.is_empty()
    }

    /// Materializes any pending correlations.
    pub fn flush(&mut self) {
        if self.pending == 0 {
            return;
        }
        let keys = keys_at(self.seed, self.offset, self.pending);
        let choices = choices_at(self.seed, self.offset, self.pending);
        let delta = self.delta;
        self.msgs.extend(keys.iter().zip(&choices).map(
            |(key, &choice)| {
                if choice { *key ^ delta } else { *key }
            },
        ));
        self.choices.extend(choices);
        self.offset += self.pending as u64;
        self.pending = 0;
        for (count, sender) in std::mem::take(&mut self.queue) {
            let len = self.choices.len();
            let choices = self.choices.split_off(len - count);
            let msgs = self.msgs.split_off(len - count);
            sender.send(RCOTReceiverOutput {
                id: self.transfer_id.next(),
                choices,
                msgs,
            });
        }
    }
}

impl RCOTReceiver<bool, Block> for EmpRCOTReceiver {
    type Error = EmpRCOTError;
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
            return Err(EmpRCOTError(format!(
                "not enough OTs: available={}, requested={count}",
                self.choices.len()
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
            self.queue.push((count, send));
        }
        Ok(recv)
    }
}

/// Mirror RCOT error.
#[derive(Debug, thiserror::Error)]
#[error("emp-mirror RCOT error: {0}")]
pub struct EmpRCOTError(String);

/// Unified emp-mirror RCOT holding both sender and receiver, for tests where
/// both roles share state (like [`crate::ideal::rcot::IdealRCOT`]).
#[derive(Debug, Clone)]
pub struct EmpRCOT {
    inner: Arc<Mutex<EmpRCOTInner>>,
}

#[derive(Debug)]
struct EmpRCOTInner {
    sender: EmpRCOTSender,
    receiver: EmpRCOTReceiver,
}

impl EmpRCOT {
    /// Creates a new mirror RCOT with the given seed and Δ.
    pub fn new(seed: Block, delta: Block) -> Self {
        let (sender, receiver) = emp_rcot(seed, delta);
        Self {
            inner: Arc::new(Mutex::new(EmpRCOTInner { sender, receiver })),
        }
    }

    /// Allocates `count` correlations for both roles.
    pub fn alloc(&mut self, count: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.sender.alloc(count).unwrap();
        inner.receiver.alloc(count).unwrap();
    }

    /// Materializes pending correlations on both roles.
    pub fn flush(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        inner.sender.flush();
        inner.receiver.flush();
    }

    /// Transfers `count` correlations.
    pub fn transfer(
        &mut self,
        count: usize,
    ) -> Result<(RCOTSenderOutput<Block>, RCOTReceiverOutput<bool, Block>), EmpRCOTError> {
        let mut inner = self.inner.lock().unwrap();
        let sender_out = inner.sender.try_send_rcot(count)?;
        let receiver_out = inner.receiver.try_recv_rcot(count)?;
        Ok((sender_out, receiver_out))
    }

    /// Returns the delta.
    pub fn delta(&self) -> Block {
        self.inner.lock().unwrap().sender.delta
    }
}

impl RCOTSender<Block> for EmpRCOT {
    type Error = EmpRCOTError;
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

impl RCOTReceiver<bool, Block> for EmpRCOT {
    type Error = EmpRCOTError;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::assert_cot;

    #[test]
    fn test_emp_rcot() {
        let seed = Block::from([7u8; 16]);
        let delta = {
            let mut b = [0x11u8; 16];
            b[0] |= 1;
            Block::from(b)
        };

        let mut rcot = EmpRCOT::new(seed, delta);
        rcot.alloc(256);
        rcot.flush();

        let (RCOTSenderOutput { keys, .. }, RCOTReceiverOutput { choices, msgs, .. }) =
            rcot.transfer(256).unwrap();

        assert_cot(delta, &choices, &keys, &msgs);
    }
}
