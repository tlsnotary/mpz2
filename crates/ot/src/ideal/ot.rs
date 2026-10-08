//! Message-based ideal Chosen-Message Oblivious Transfer functionality.
//!
//! This implementation wraps `ot-core`'s `IdealOTSender`/`IdealOTReceiver`
//! and adds async I/O for network communication.

use async_trait::async_trait;
use mpz_common::{Context, Flush, future::MaybeDone};
use mpz_core::Block;
use mpz_ot_core::{
    ideal::ot::{
        FlushMsg, IdealOTError as CoreError, IdealOTReceiver as CoreReceiver,
        IdealOTSender as CoreSender,
    },
    ot::{OTReceiver, OTReceiverOutput, OTSender, OTSenderOutput},
};
use serio::{SinkExt, stream::IoStreamExt};

/// Returns a new ideal OT sender and receiver.
pub fn ideal_ot() -> (IdealOTSender, IdealOTReceiver) {
    (
        IdealOTSender {
            core: CoreSender::new(),
        },
        IdealOTReceiver {
            core: CoreReceiver::new(),
        },
    )
}

/// Message-based ideal OT sender.
///
/// Wraps `ot-core`'s `IdealOTSender` and sends `FlushMsg` over the network.
pub struct IdealOTSender {
    core: CoreSender,
}

impl OTSender<Block> for IdealOTSender {
    type Error = IdealOTError;
    type Future = MaybeDone<OTSenderOutput>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        OTSender::alloc(&mut self.core, count).map_err(From::from)
    }

    fn queue_send_ot(&mut self, msgs: &[[Block; 2]]) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_ot(msgs).map_err(From::from)
    }
}

#[async_trait]
impl Flush for IdealOTSender {
    type Error = IdealOTError;

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

/// Message-based ideal OT receiver.
///
/// Wraps `ot-core`'s `IdealOTReceiver` and receives `FlushMsg` from the
/// network.
pub struct IdealOTReceiver {
    core: CoreReceiver,
}

impl OTReceiver<bool, Block> for IdealOTReceiver {
    type Error = IdealOTError;
    type Future = MaybeDone<OTReceiverOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        OTReceiver::alloc(&mut self.core, count).map_err(From::from)
    }

    fn queue_recv_ot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_ot(choices).map_err(From::from)
    }
}

#[async_trait]
impl Flush for IdealOTReceiver {
    type Error = IdealOTError;

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

/// Ideal OT error.
#[derive(Debug, thiserror::Error)]
pub enum IdealOTError {
    /// Core error.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// I/O error during message exchange.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use mpz_common::{context::test_st_context, future::Output};
    use mpz_ot_core::test::assert_ot;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;

    #[tokio::test]
    async fn test_ideal_ot() {
        let mut rng = StdRng::seed_from_u64(0);

        let (mut sender, mut receiver) = ideal_ot();
        let (mut ctx_s, mut ctx_r) = test_st_context(1024 * 1024);

        // Generate messages and choices
        let msgs: Vec<[Block; 2]> = (0..128).map(|_| [rng.random(), rng.random()]).collect();
        let choices: Vec<bool> = (0..128).map(|_| rng.random()).collect();

        // Queue operations
        let mut sender_out = sender.queue_send_ot(&msgs).unwrap();
        let mut receiver_out = receiver.queue_recv_ot(&choices).unwrap();

        // Flush
        let (r1, r2) = futures::join!(sender.flush(&mut ctx_s), receiver.flush(&mut ctx_r));
        r1.unwrap();
        r2.unwrap();

        // Get outputs
        let _ = sender_out.try_recv().unwrap().unwrap();
        let receiver_output = receiver_out.try_recv().unwrap().unwrap();

        // Verify correctness
        assert_ot(&choices, &msgs, &receiver_output.msgs);
    }
}
