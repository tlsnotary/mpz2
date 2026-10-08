//! Message-based ideal Random Correlated Oblivious Transfer functionality.
//!
//! This implementation wraps `ot-core`'s `IdealRCOTSender`/`IdealRCOTReceiver`
//! and adds async I/O for network communication.

use async_trait::async_trait;
use mpz_common::{Context, Flush, future::MaybeDone};
use mpz_core::Block;
use mpz_ot_core::{
    ideal::rcot::{
        FlushMsg, IdealRCOTError as CoreError, IdealRCOTReceiver as CoreReceiver,
        IdealRCOTSender as CoreSender,
    },
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
};
use serio::{SinkExt, stream::IoStreamExt};

/// Returns a new message-based ideal RCOT sender and receiver.
pub fn ideal_rcot(seed: Block, delta: Block) -> (IdealRCOTSender, IdealRCOTReceiver) {
    (
        IdealRCOTSender {
            core: CoreSender::new(seed, delta),
        },
        IdealRCOTReceiver {
            core: CoreReceiver::new(),
        },
    )
}

/// Message-based ideal RCOT sender.
///
/// Wraps `ot-core`'s `IdealRCOTSender` and sends `FlushMsg` over the network.
pub struct IdealRCOTSender {
    core: CoreSender,
}

impl IdealRCOTSender {
    /// Creates a new sender with the given seed and delta.
    pub fn new(seed: Block, delta: Block) -> Self {
        Self {
            core: CoreSender::new(seed, delta),
        }
    }
}

impl RCOTSender<Block> for IdealRCOTSender {
    type Error = IdealRCOTError;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        RCOTSender::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        RCOTSender::available(&self.core)
    }

    fn delta(&self) -> Block {
        self.core.delta()
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        self.core.try_send_rcot(count).map_err(From::from)
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_rcot(count).map_err(From::from)
    }
}

#[async_trait]
impl Flush for IdealRCOTSender {
    type Error = IdealRCOTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        if let Some(msg) = self.core.flush() {
            ctx.io_mut().send(msg).await?;
        }
        Ok(())
    }
}

/// Message-based ideal RCOT receiver.
///
/// Wraps `ot-core`'s `IdealRCOTReceiver` and receives `FlushMsg` from the
/// network.
pub struct IdealRCOTReceiver {
    core: CoreReceiver,
}

impl IdealRCOTReceiver {
    /// Creates a new receiver with the given seed for deterministic behavior.
    pub fn from_seed(seed: u64) -> Self {
        Self {
            core: CoreReceiver::from_seed(seed),
        }
    }
}

impl RCOTReceiver<bool, Block> for IdealRCOTReceiver {
    type Error = IdealRCOTError;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        RCOTReceiver::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        RCOTReceiver::available(&self.core)
    }

    fn try_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        self.core.try_recv_rcot(count).map_err(From::from)
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_rcot(count).map_err(From::from)
    }
}

#[async_trait]
impl Flush for IdealRCOTReceiver {
    type Error = IdealRCOTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            let msg: FlushMsg = ctx.io_mut().expect_next().await?;
            self.core.flush(msg)?;
        }
        Ok(())
    }
}

/// Ideal RCOT error.
#[derive(Debug, thiserror::Error)]
pub enum IdealRCOTError {
    /// Core error.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// I/O error during message exchange.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use mpz_common::context::test_st_context;
    use mpz_ot_core::test::assert_cot;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;

    #[tokio::test]
    async fn test_ideal_rcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta: Block = rng.random();

        let (mut sender, mut receiver) = ideal_rcot(rng.random(), delta);
        let (mut ctx_s, mut ctx_r) = test_st_context(1024 * 1024);

        const COUNT: usize = 128;

        // Allocate
        RCOTSender::alloc(&mut sender, COUNT).unwrap();
        RCOTReceiver::alloc(&mut receiver, COUNT).unwrap();

        // Flush (exchange seed only)
        let (r1, r2) = futures::join!(sender.flush(&mut ctx_s), receiver.flush(&mut ctx_r));
        r1.unwrap();
        r2.unwrap();

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
}
