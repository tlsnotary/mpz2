//! Message-based ideal Random Oblivious Transfer functionality.
//!
//! This implementation wraps `ot-core`'s `IdealROTSender`/`IdealROTReceiver`
//! and adds async I/O for network communication.

use async_trait::async_trait;
use mpz_common::{Context, Flush, future::MaybeDone};
use mpz_core::Block;
use mpz_ot_core::{
    ideal::rot::{
        FlushMsg, IdealROTError as CoreError, IdealROTReceiver as CoreReceiver,
        IdealROTSender as CoreSender,
    },
    rot::{ROTReceiver, ROTReceiverOutput, ROTSender, ROTSenderOutput},
};
use serio::{SinkExt, stream::IoStreamExt};

/// Returns a new ideal ROT sender and receiver.
pub fn ideal_rot(seed: Block) -> (IdealROTSender, IdealROTReceiver) {
    (
        IdealROTSender {
            core: CoreSender::new(seed),
        },
        IdealROTReceiver {
            core: CoreReceiver::new(),
        },
    )
}

/// Message-based ideal ROT sender.
///
/// Wraps `ot-core`'s `IdealROTSender` and sends `FlushMsg` over the network.
pub struct IdealROTSender {
    core: CoreSender,
}

impl ROTSender<[Block; 2]> for IdealROTSender {
    type Error = IdealROTError;
    type Future = MaybeDone<ROTSenderOutput<[Block; 2]>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        ROTSender::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        ROTSender::available(&self.core)
    }

    fn try_send_rot(&mut self, count: usize) -> Result<ROTSenderOutput<[Block; 2]>, Self::Error> {
        self.core.try_send_rot(count).map_err(From::from)
    }

    fn queue_send_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_rot(count).map_err(From::from)
    }
}

#[async_trait]
impl Flush for IdealROTSender {
    type Error = IdealROTError;

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

/// Message-based ideal ROT receiver.
///
/// Wraps `ot-core`'s `IdealROTReceiver` and receives `FlushMsg` from the
/// network.
pub struct IdealROTReceiver {
    core: CoreReceiver,
}

impl ROTReceiver<bool, Block> for IdealROTReceiver {
    type Error = IdealROTError;
    type Future = MaybeDone<ROTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        ROTReceiver::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        ROTReceiver::available(&self.core)
    }

    fn try_recv_rot(
        &mut self,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, Block>, Self::Error> {
        self.core.try_recv_rot(count).map_err(From::from)
    }

    fn queue_recv_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_rot(count).map_err(From::from)
    }
}

#[async_trait]
impl Flush for IdealROTReceiver {
    type Error = IdealROTError;

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

/// Ideal ROT error.
#[derive(Debug, thiserror::Error)]
pub enum IdealROTError {
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
    use mpz_ot_core::test::assert_rot;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;

    #[tokio::test]
    async fn test_ideal_rot() {
        let mut rng = StdRng::seed_from_u64(0);

        let (mut sender, mut receiver) = ideal_rot(rng.random());
        let (mut ctx_s, mut ctx_r) = test_st_context(1024 * 1024);

        const COUNT: usize = 128;

        // Allocate
        ROTSender::alloc(&mut sender, COUNT).unwrap();
        ROTReceiver::alloc(&mut receiver, COUNT).unwrap();

        // Flush (exchange seed only)
        let (r1, r2) = futures::join!(sender.flush(&mut ctx_s), receiver.flush(&mut ctx_r));
        r1.unwrap();
        r2.unwrap();

        // Transfer
        let sender_out = sender.try_send_rot(COUNT).unwrap();
        let receiver_out = receiver.try_recv_rot(COUNT).unwrap();

        // Verify correctness
        assert_rot(&receiver_out.choices, &sender_out.keys, &receiver_out.msgs);
    }
}
