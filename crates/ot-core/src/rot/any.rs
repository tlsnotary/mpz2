use mpz_common::future::{Map, OutputExt};
use mpz_core::{Block, prg::Prg};
use rand::{RngExt, distr::StandardUniform, prelude::Distribution};

use crate::rot::{ROTReceiver, ROTReceiverOutput, ROTSender, ROTSenderOutput};

/// A ROT sender which sends any type implementing `rand` traits.
#[derive(Debug)]
pub struct AnySender<T> {
    rot: T,
}

impl<T> AnySender<T> {
    /// Creates a new `AnySender`.
    pub fn new(rot: T) -> Self {
        Self { rot }
    }

    /// Returns a reference to the inner sender.
    pub fn rot(&self) -> &T {
        &self.rot
    }

    /// Returns a mutable reference to the inner sender.
    pub fn rot_mut(&mut self) -> &mut T {
        &mut self.rot
    }

    /// Returns the inner sender.
    pub fn into_inner(self) -> T {
        self.rot
    }
}

impl<T, U> ROTSender<[U; 2]> for AnySender<T>
where
    T: ROTSender<[Block; 2]>,
    StandardUniform: Distribution<U>,
{
    type Error = T::Error;
    type Future = Map<
        T::Future,
        ROTSenderOutput<[Block; 2]>,
        fn(ROTSenderOutput<[Block; 2]>) -> ROTSenderOutput<[U; 2]>,
    >;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.rot.alloc(count)
    }

    fn available(&self) -> usize {
        self.rot.available()
    }

    fn try_send_rot(&mut self, count: usize) -> Result<ROTSenderOutput<[U; 2]>, Self::Error> {
        self.rot.try_send_rot(count).map(map_sender)
    }

    fn queue_send_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.rot
            .queue_send_rot(count)
            .map(|output| output.map(map_sender as fn(_) -> _))
    }
}

fn map_sender<T>(output: ROTSenderOutput<[Block; 2]>) -> ROTSenderOutput<[T; 2]>
where
    StandardUniform: Distribution<T>,
{
    let ROTSenderOutput { id, keys } = output;
    let keys = keys
        .into_iter()
        .map(|[k0, k1]| {
            let mut prg_0 = Prg::new_with_seed(k0.to_bytes());
            let mut prg_1 = Prg::new_with_seed(k1.to_bytes());

            [prg_0.random(), prg_1.random()]
        })
        .collect();
    ROTSenderOutput { id, keys }
}

/// A ROT receiver which receives any type implementing `rand` traits.
#[derive(Debug)]
pub struct AnyReceiver<T> {
    rot: T,
}

impl<T> AnyReceiver<T> {
    /// Creates a new `AnyReceiver`.
    pub fn new(rot: T) -> Self {
        Self { rot }
    }

    /// Returns a reference to the inner receiver.
    pub fn rot(&self) -> &T {
        &self.rot
    }

    /// Returns a mutable reference to the inner receiver.
    pub fn rot_mut(&mut self) -> &mut T {
        &mut self.rot
    }

    /// Returns the inner receiver.
    pub fn into_inner(self) -> T {
        self.rot
    }
}

impl<T, U> ROTReceiver<bool, U> for AnyReceiver<T>
where
    T: ROTReceiver<bool, Block>,
    StandardUniform: Distribution<U>,
{
    type Error = T::Error;
    type Future = Map<
        T::Future,
        ROTReceiverOutput<bool, Block>,
        fn(ROTReceiverOutput<bool, Block>) -> ROTReceiverOutput<bool, U>,
    >;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.rot.alloc(count)
    }

    fn available(&self) -> usize {
        self.rot.available()
    }

    fn try_recv_rot(&mut self, count: usize) -> Result<ROTReceiverOutput<bool, U>, Self::Error> {
        self.rot.try_recv_rot(count).map(map_receiver)
    }

    fn queue_recv_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.rot
            .queue_recv_rot(count)
            .map(|output| output.map(map_receiver as fn(_) -> _))
    }
}

fn map_receiver<T>(output: ROTReceiverOutput<bool, Block>) -> ROTReceiverOutput<bool, T>
where
    StandardUniform: Distribution<T>,
{
    let ROTReceiverOutput { id, choices, msgs } = output;
    let msgs = msgs
        .into_iter()
        .map(|msg| {
            let mut prg = Prg::new_with_seed(msg.to_bytes());
            prg.random()
        })
        .collect();
    ROTReceiverOutput { id, choices, msgs }
}
