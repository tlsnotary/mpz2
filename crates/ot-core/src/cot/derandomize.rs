use std::{collections::VecDeque, mem};

use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_core::{Block, bitvec::BitVec};
use serde::{Deserialize, Serialize};

use crate::{
    Derandomize,
    cot::{COTReceiver, COTReceiverOutput, COTSender, COTSenderOutput},
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
};

/// COT adjustment message.
#[derive(Debug, Serialize, Deserialize)]
pub struct Adjust<T> {
    adjust: Vec<T>,
}

#[derive(Debug)]
struct QueuedSend {
    count: usize,
    sender: Sender<COTSenderOutput>,
}

/// Derandomized COT sender.
///
/// This is a COT sender which derandomizes preprocessed RCOTs.
#[derive(Debug)]
pub struct DerandCOTSender<T> {
    rcot: T,
    /// Keys corresponding to the value 0 of the choice bits which need to be
    /// derandomized.
    adjust: Vec<Block>,
    queue: VecDeque<QueuedSend>,
}

impl<T> DerandCOTSender<T> {
    /// Creates a new `DerandCOTSender`.
    pub fn new(rcot: T) -> Self {
        Self {
            rcot,
            adjust: Vec::new(),
            queue: VecDeque::new(),
        }
    }

    /// Returns a reference to the RCOT sender.
    pub fn rcot(&self) -> &T {
        &self.rcot
    }

    /// Returns a mutable reference to the RCOT sender.
    pub fn rcot_mut(&mut self) -> &mut T {
        &mut self.rcot
    }

    /// Returns the inner RCOT sender.
    pub fn into_inner(self) -> T {
        self.rcot
    }
}

impl<T> DerandCOTSender<T>
where
    T: RCOTSender<Block>,
{
    /// Returns `true` if the sender wants to send adjustments.
    pub fn wants_adjust(&self) -> bool {
        !self.adjust.is_empty()
    }

    /// Returns the adjustment message.
    pub fn adjust(
        &mut self,
        derandomize: Derandomize,
    ) -> Result<Adjust<Block>, DerandCOTSenderError> {
        let Derandomize { flip } = derandomize;

        if flip.len() != self.adjust.len() {
            return Err(DerandCOTSenderError::new(format!(
                "derandomize is wrong length: {} != {}",
                flip.len(),
                self.adjust.len()
            )));
        }

        let mut i = 0;
        let delta = self.delta();
        let mut adjust = mem::take(&mut self.adjust);
        for QueuedSend { count, sender } in mem::take(&mut self.queue) {
            let RCOTSenderOutput { id, keys } = self
                .rcot
                .try_send_rcot(count)
                .map_err(DerandCOTSenderError::new)?;

            adjust[i..i + count]
                .iter_mut()
                .zip(&flip[i..i + count])
                .zip(keys)
                .for_each(|((adjust, flip), key)| {
                    *adjust ^= key;
                    *adjust ^= if *flip { delta } else { Block::ZERO };
                });

            i += count;

            sender.send(COTSenderOutput { id });
        }

        Ok(Adjust { adjust })
    }
}

impl<T> COTSender<Block> for DerandCOTSender<T>
where
    T: RCOTSender<Block>,
{
    type Error = DerandCOTSenderError;
    type Future = MaybeDone<COTSenderOutput>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.rcot.alloc(count).map_err(DerandCOTSenderError::new)
    }

    fn available(&self) -> usize {
        self.rcot.available()
    }

    fn delta(&self) -> Block {
        self.rcot.delta()
    }

    fn queue_send_cot(&mut self, keys: &[Block]) -> Result<Self::Future, Self::Error> {
        let count = keys.len();
        let (sender, recv) = new_output();

        self.adjust.extend_from_slice(keys);
        self.queue.push_back(QueuedSend { count, sender });

        Ok(recv)
    }
}

/// Error for [`DerandCOTSender`].
#[derive(Debug, thiserror::Error)]
#[error("derandomized COT sender error: {source}")]
pub struct DerandCOTSenderError {
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl DerandCOTSenderError {
    fn new<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self { source: err.into() }
    }
}

#[derive(Debug)]
struct QueuedReceive {
    count: usize,
    sender: Sender<COTReceiverOutput<Block>>,
}

/// Derandomized COT receiver.
#[derive(Debug)]
pub struct DerandCOTReceiver<T> {
    rcot: T,
    /// Choice bits from RCOT which need to be derandomized.
    derandomize: BitVec,
    queue: VecDeque<QueuedReceive>,
}

impl<T> DerandCOTReceiver<T> {
    /// Creates a new `DerandCOTReceiver`.
    pub fn new(rcot: T) -> Self {
        Self {
            rcot,
            derandomize: BitVec::new(),
            queue: VecDeque::new(),
        }
    }

    /// Returns a reference to the RCOT receiver.
    pub fn rcot(&self) -> &T {
        &self.rcot
    }

    /// Returns a mutable reference to the RCOT receiver.
    pub fn rcot_mut(&mut self) -> &mut T {
        &mut self.rcot
    }

    /// Returns the inner RCOT receiver.
    pub fn into_inner(self) -> T {
        self.rcot
    }
}

impl<T> DerandCOTReceiver<T>
where
    T: RCOTReceiver<bool, Block>,
{
    /// Returns `true` if the receiver wants to adjust COTs.
    pub fn wants_adjust(&self) -> bool {
        !self.derandomize.is_empty()
    }

    /// Adjusts the COTs.
    pub fn adjust(
        &mut self,
    ) -> Result<(Derandomize, ReceiveAdjust<'_, T>), DerandCOTReceiverError> {
        let mut flip = mem::take(&mut self.derandomize);
        let mut cots = Vec::new();
        let mut i = 0;
        for QueuedReceive { count, .. } in self.queue.iter() {
            let count = *count;
            if self.rcot.available() < count {
                break;
            }

            let RCOTReceiverOutput {
                id,
                choices: masks,
                msgs,
            } = self
                .rcot
                .try_recv_rcot(count)
                .map_err(DerandCOTReceiverError::new)?;

            // Mask choice bits.
            flip[i..i + count]
                .iter_mut()
                .zip(masks)
                .for_each(|(mut choice, mask)| *choice ^= mask);

            cots.push(COTReceiverOutput { id, msgs });
            i += count;
        }

        Ok((
            Derandomize { flip },
            ReceiveAdjust {
                recv: self,
                cots,
                count: i,
            },
        ))
    }
}

/// Receiver returned by [`DerandCOTReceiver::adjust`].
#[must_use]
pub struct ReceiveAdjust<'a, T> {
    recv: &'a mut DerandCOTReceiver<T>,
    count: usize,
    cots: Vec<COTReceiverOutput<Block>>,
}

impl<T> ReceiveAdjust<'_, T>
where
    T: RCOTReceiver<bool, Block>,
{
    /// Receives the adjusted COTs.
    pub fn receive(self, adjust: Adjust<Block>) -> Result<(), DerandCOTReceiverError> {
        let Adjust { adjust } = adjust;

        if adjust.len() != self.count {
            return Err(DerandCOTReceiverError::new(format!(
                "adjust is wrong length: {} != {}",
                adjust.len(),
                self.count
            )));
        }

        let mut adjust = adjust.into_iter();
        let n = self.cots.len();
        for (mut output, QueuedReceive { sender, .. }) in
            self.cots.into_iter().zip(self.recv.queue.drain(..n))
        {
            output
                .msgs
                .iter_mut()
                .zip(adjust.by_ref())
                .for_each(|(msg, adjust)| *msg ^= adjust);

            sender.send(output);
        }

        Ok(())
    }
}

impl<T> COTReceiver<bool, Block> for DerandCOTReceiver<T>
where
    T: RCOTReceiver<bool, Block>,
{
    type Error = DerandCOTReceiverError;
    type Future = MaybeDone<COTReceiverOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.rcot.alloc(count).map_err(DerandCOTReceiverError::new)
    }

    fn available(&self) -> usize {
        self.rcot.available()
    }

    fn queue_recv_cot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        let count = choices.len();
        let (sender, recv) = new_output();

        self.derandomize.extend(choices.iter().copied());
        self.queue.push_back(QueuedReceive { count, sender });

        Ok(recv)
    }
}

/// Error for [`DerandCOTReceiver`].
#[derive(Debug, thiserror::Error)]
#[error("derandomized COT receiver error: {source}")]
pub struct DerandCOTReceiverError {
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl DerandCOTReceiverError {
    fn new<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self { source: err.into() }
    }
}

#[cfg(test)]
mod tests {
    use mpz_common::future::Output;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use crate::{ideal::rcot::IdealRCOT, test::assert_cot};

    use super::*;

    #[test]
    fn test_derandomize_cot() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Block::random(&mut rng);
        let rcot = IdealRCOT::new(rng.random(), delta);

        let mut sender = DerandCOTSender::new(rcot.clone());
        let mut receiver = DerandCOTReceiver::new(rcot);

        let count = 10;
        let choices = (0..count).map(|_| rng.random()).collect::<Vec<_>>();
        let keys: Vec<_> = (0..count).map(|_| Block::random(&mut rng)).collect();

        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();

        std::mem::drop(sender.queue_send_cot(&keys).unwrap());
        std::mem::drop(receiver.queue_recv_cot(&choices).unwrap());

        for _ in 0..8 {
            sender.alloc(count).unwrap();
            receiver.alloc(count).unwrap();
            sender.rcot_mut().flush().unwrap();

            let mut sender_output = sender.queue_send_cot(&keys).unwrap();
            let mut receiver_output = receiver.queue_recv_cot(&choices).unwrap();

            assert!(sender.wants_adjust());
            assert!(receiver.wants_adjust());

            let (derandomize, recv) = receiver.adjust().unwrap();
            let adjust = sender.adjust(derandomize).unwrap();
            recv.receive(adjust).unwrap();

            let COTSenderOutput { id: sender_id } = sender_output.try_recv().unwrap().unwrap();
            let COTReceiverOutput {
                id: receiver_id,
                msgs,
            } = receiver_output.try_recv().unwrap().unwrap();

            assert_eq!(sender_id, receiver_id);
            assert_cot(delta, &choices, &keys, &msgs);
        }
    }
}
