//! A simple 2-party coin-toss protocol.
//!
//! # Example
//!
//! ```
//! use mpz_core::Block;
//! use mpz_common::context::test_st_context;
//! use mpz_cointoss::{cointoss_receiver, cointoss_sender};
//! # use mpz_cointoss::CointossError;
//! # use futures::executor::block_on;
//!
//! # fn main() {
//! # block_on(async {
//! let (mut ctx_sender, mut ctx_receiver) = test_st_context(8);
//! let sender_seeds = (0..8).map(|_| Block::random(&mut rand::rng())).collect();
//! let receiver_seeds = (0..8).map(|_| Block::random(&mut rand::rng())).collect();
//!
//! let (sender_output, receiver_output) =
//!     futures::try_join!(
//!         cointoss_sender(&mut ctx_sender, sender_seeds),
//!         cointoss_receiver(&mut ctx_receiver, receiver_seeds),
//!     )?;
//!
//! assert_eq!(sender_output, receiver_output);
//! # Ok::<_, CointossError>(())
//! # }).unwrap();
//! # }
//! ```

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

use mpz_cointoss_core::{
    CointossError as CoreError, Receiver as CoreReceiver, Sender as CoreSender,
};
use mpz_common::Context;
use mpz_core::Block;
use serio::{SinkExt, stream::IoStreamExt};

pub use mpz_cointoss_core::{msgs, receiver_state, sender_state};

/// Coin-toss protocol error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CointossError {
    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A core error occurred.
    #[error("core error: {0}")]
    Core(#[from] CoreError),
}

/// A coin-toss sender.
#[derive(Debug)]
pub struct Sender<T: sender_state::State = sender_state::Initialized> {
    inner: CoreSender<T>,
}

impl Sender {
    /// Create a new sender.
    pub fn new(seeds: Vec<Block>) -> Self {
        Self {
            inner: CoreSender::new(seeds),
        }
    }

    /// Sends the coin-toss commitment.
    pub async fn commit(
        self,
        ctx: &mut Context,
    ) -> Result<Sender<sender_state::Committed>, CointossError> {
        let (inner, commitment) = self.inner.send();
        ctx.io_mut().send(commitment).await?;
        Ok(Sender { inner })
    }

    /// Executes the coin-toss protocol to completion.
    pub async fn execute(self, ctx: &mut Context) -> Result<Vec<Block>, CointossError> {
        let (seeds, sender) = self.commit(ctx).await?.receive(ctx).await?;
        sender.finalize(ctx).await?;
        Ok(seeds)
    }
}

impl Sender<sender_state::Committed> {
    /// Receives the receiver's payload and computes the output of the
    /// coin-toss.
    pub async fn receive(
        self,
        ctx: &mut Context,
    ) -> Result<(Vec<Block>, Sender<sender_state::Received>), CointossError> {
        let payload = ctx.io_mut().expect_next().await?;
        let (seeds, sender) = self.inner.receive(payload)?;
        Ok((seeds, Sender { inner: sender }))
    }
}

impl Sender<sender_state::Received> {
    /// Finalizes the coin-toss, decommitting the sender's seeds.
    pub async fn finalize(self, ctx: &mut Context) -> Result<(), CointossError> {
        ctx.io_mut().send(self.inner.finalize()).await?;
        Ok(())
    }
}

/// A coin-toss receiver.
#[derive(Debug)]
pub struct Receiver<T: receiver_state::State = receiver_state::Initialized> {
    inner: CoreReceiver<T>,
}

impl Receiver {
    /// Create a new receiver.
    pub fn new(seeds: Vec<Block>) -> Self {
        Self {
            inner: CoreReceiver::new(seeds),
        }
    }

    /// Reveals the receiver's seeds after receiving the sender's commitment.
    pub async fn receive(
        self,
        ctx: &mut Context,
    ) -> Result<Receiver<receiver_state::Received>, CointossError> {
        let commitment = ctx.io_mut().expect_next().await?;
        let (inner, payload) = self.inner.reveal(commitment)?;
        ctx.io_mut().send(payload).await?;
        Ok(Receiver { inner })
    }

    /// Executes the coin-toss protocol to completion.
    pub async fn execute(self, ctx: &mut Context) -> Result<Vec<Block>, CointossError> {
        self.receive(ctx).await?.finalize(ctx).await
    }
}

impl Receiver<receiver_state::Received> {
    /// Finalizes the coin-toss, returning the random seeds.
    pub async fn finalize(self, ctx: &mut Context) -> Result<Vec<Block>, CointossError> {
        let payload = ctx.io_mut().expect_next().await?;
        let seeds = self.inner.finalize(payload)?;
        Ok(seeds)
    }
}

/// Executes the coin-toss protocol as the sender.
///
/// # Arguments
///
/// * `ctx` - The thread context.
/// * `seeds` - The seeds to use for the coin-toss.
pub async fn cointoss_sender(
    ctx: &mut Context,
    seeds: Vec<Block>,
) -> Result<Vec<Block>, CointossError> {
    Sender::new(seeds).execute(ctx).await
}

/// Executes the coin-toss protocol as the receiver.
///
/// # Arguments
///
/// * `ctx` - The thread context.
/// * `seeds` - The seeds to use for the coin-toss.
pub async fn cointoss_receiver(
    ctx: &mut Context,
    seeds: Vec<Block>,
) -> Result<Vec<Block>, CointossError> {
    Receiver::new(seeds).execute(ctx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::executor::block_on;
    use mpz_common::context::test_st_context;

    #[test]
    fn test_cointoss() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        block_on(async {
            futures::try_join!(
                cointoss_sender(&mut ctx_a, vec![Block::ZERO, Block::ONES]),
                cointoss_receiver(&mut ctx_b, vec![Block::ONES, Block::ZERO]),
            )
            .unwrap()
        });
    }
}
