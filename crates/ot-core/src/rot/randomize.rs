use mpz_common::future::{Map, OutputExt};
use mpz_core::{Block, aes::FIXED_KEY_AES};

use crate::{
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
    rot::{ROTReceiver, ROTReceiverOutput, ROTSender, ROTSenderOutput},
};

// We have to Box the closure because it's not name-able in the associated type.
type FnSender = Box<dyn FnOnce(RCOTSenderOutput<Block>) -> ROTSenderOutput<[Block; 2]> + Send>;

/// ROT sender which randomizes the output of an RCOT sender.
#[derive(Debug)]
pub struct RandomizeRCOTSender<T> {
    rcot: T,
}

impl<T> RandomizeRCOTSender<T> {
    /// Creates a new [`RandomizeRCOTSender`].
    ///
    /// # Arguments
    ///
    /// * `rcot` - RCOT sender.
    pub fn new(rcot: T) -> Self {
        Self { rcot }
    }

    /// Returns a reference to the RCOT sender.
    pub fn rcot(&self) -> &T {
        &self.rcot
    }

    /// Returns a mutable reference to the RCOT sender.
    pub fn rcot_mut(&mut self) -> &mut T {
        &mut self.rcot
    }

    /// Returns the RCOT sender.
    pub fn into_inner(self) -> T {
        self.rcot
    }
}

impl<T> ROTSender<[Block; 2]> for RandomizeRCOTSender<T>
where
    T: RCOTSender<Block>,
{
    type Error = T::Error;
    type Future = Map<T::Future, RCOTSenderOutput<Block>, FnSender>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.rcot.alloc(count)
    }

    fn available(&self) -> usize {
        self.rcot.available()
    }

    fn try_send_rot(&mut self, count: usize) -> Result<ROTSenderOutput<[Block; 2]>, Self::Error> {
        let delta = self.rcot.delta();
        self.rcot
            .try_send_rcot(count)
            .map(|output| randomize_sender(delta, output))
    }

    fn queue_send_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let delta = self.rcot.delta();
        self.rcot.queue_send_rcot(count).map(move |output| {
            output.map(Box::new(move |output| randomize_sender(delta, output)) as FnSender)
        })
    }
}

fn randomize_sender(delta: Block, output: RCOTSenderOutput<Block>) -> ROTSenderOutput<[Block; 2]> {
    let RCOTSenderOutput { id, keys } = output;

    cfg_if::cfg_if! {
        if #[cfg(feature = "rayon")] {
            use rayon::prelude::*;
            let iter = keys.into_par_iter().enumerate();
        } else {
            let iter = keys.into_iter().enumerate();
        }
    }

    let cipher = &(*FIXED_KEY_AES);
    let keys = iter
        .map(|(i, key)| {
            // Transfer ID ensures a unique tweak for each ROT.
            let j = ((id.as_u64() as u128) << 64) + (i as u128);
            let j = Block::new(j.to_be_bytes());

            let k0 = cipher.tccr(j, key);
            let k1 = cipher.tccr(j, key ^ delta);

            [k0, k1]
        })
        .collect();

    ROTSenderOutput { id, keys }
}

/// ROT receiver which randomizes the output of an RCOT receiver.
#[derive(Debug)]
pub struct RandomizeRCOTReceiver<T> {
    rcot: T,
}

impl<T> RandomizeRCOTReceiver<T> {
    /// Creates a new [`RandomizeRCOTReceiver`].
    ///
    /// # Arguments
    ///
    /// * `rcot` - RCOT receiver.
    pub fn new(rcot: T) -> Self {
        Self { rcot }
    }

    /// Returns a reference to the RCOT receiver.
    pub fn rcot(&self) -> &T {
        &self.rcot
    }

    /// Returns a mutable reference to the RCOT receiver.
    pub fn rcot_mut(&mut self) -> &mut T {
        &mut self.rcot
    }

    /// Returns the RCOT receiver.
    pub fn into_inner(self) -> T {
        self.rcot
    }
}

impl<T> ROTReceiver<bool, Block> for RandomizeRCOTReceiver<T>
where
    T: RCOTReceiver<bool, Block>,
{
    type Error = T::Error;
    type Future = Map<
        T::Future,
        RCOTReceiverOutput<bool, Block>,
        fn(RCOTReceiverOutput<bool, Block>) -> ROTReceiverOutput<bool, Block>,
    >;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.rcot.alloc(count)
    }

    fn available(&self) -> usize {
        self.rcot.available()
    }

    fn try_recv_rot(
        &mut self,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, Block>, Self::Error> {
        self.rcot.try_recv_rcot(count).map(randomize_receiver)
    }

    fn queue_recv_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.rcot
            .queue_recv_rcot(count)
            .map(|output| output.map(randomize_receiver as fn(_) -> _))
    }
}

fn randomize_receiver(output: RCOTReceiverOutput<bool, Block>) -> ROTReceiverOutput<bool, Block> {
    let RCOTReceiverOutput {
        id,
        choices,
        mut msgs,
    } = output;

    cfg_if::cfg_if! {
        if #[cfg(feature = "rayon")] {
            use rayon::prelude::*;
            let iter = msgs.par_iter_mut().enumerate();
        } else {
            let iter = msgs.iter_mut().enumerate();
        }
    }

    let cipher = &(*FIXED_KEY_AES);
    iter.for_each(|(i, msg)| {
        // Transfer ID ensures a unique tweak for each ROT.
        let j = ((id.as_u64() as u128) << 64) + (i as u128);
        let j = Block::new(j.to_be_bytes());

        *msg = cipher.tccr(j, *msg);
    });

    ROTReceiverOutput { id, choices, msgs }
}

#[cfg(test)]
mod tests {
    use mpz_common::future::Output;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;

    use crate::{ideal::rcot::IdealRCOT, test::assert_rot};

    #[test]
    fn test_randomize_rcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let rcot = IdealRCOT::new(rng.random(), rng.random());

        let mut sender = RandomizeRCOTSender::new(rcot.clone());
        let mut receiver = RandomizeRCOTReceiver::new(rcot);

        let count = 128;
        sender.alloc(count).unwrap();
        let mut sender_output = sender.queue_send_rot(count).unwrap();

        receiver.alloc(count).unwrap();
        let mut receiver_output = receiver.queue_recv_rot(count).unwrap();

        sender.rcot_mut().flush().unwrap();

        let ROTSenderOutput {
            id: sender_id,
            keys,
        } = sender_output.try_recv().unwrap().unwrap();
        let ROTReceiverOutput {
            id: receiver_id,
            choices,
            msgs,
        } = receiver_output.try_recv().unwrap().unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_rot(&choices, &keys, &msgs);
    }
}
