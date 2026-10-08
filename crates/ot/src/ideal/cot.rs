//! Message-based ideal Correlated Oblivious Transfer functionality.
//!
//! This implementation wraps `ot-core`'s `IdealCOTSender`/`IdealCOTReceiver`
//! and adds async I/O for network communication.

use async_trait::async_trait;
use mpz_common::{Context, Flush, future::MaybeDone};
use mpz_core::Block;
use mpz_ot_core::{
    cot::{COTReceiver, COTReceiverOutput, COTSender, COTSenderOutput},
    ideal::cot::{
        FlushMsg, IdealCOTError as CoreError, IdealCOTReceiver as CoreReceiver,
        IdealCOTSender as CoreSender,
    },
};
use serio::{SinkExt, stream::IoStreamExt};

/// Returns a new ideal COT sender and receiver.
pub fn ideal_cot(delta: Block) -> (IdealCOTSender, IdealCOTReceiver) {
    (
        IdealCOTSender {
            core: CoreSender::new(delta),
        },
        IdealCOTReceiver {
            core: CoreReceiver::new(),
        },
    )
}

/// Message-based ideal COT sender.
///
/// Wraps `ot-core`'s `IdealCOTSender` and sends `FlushMsg` over the network.
pub struct IdealCOTSender {
    core: CoreSender,
}

impl COTSender<Block> for IdealCOTSender {
    type Error = IdealCOTError;
    type Future = MaybeDone<COTSenderOutput>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        COTSender::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        COTSender::available(&self.core)
    }

    fn delta(&self) -> Block {
        self.core.delta()
    }

    fn queue_send_cot(&mut self, keys: &[Block]) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_cot(keys).map_err(From::from)
    }
}

#[async_trait]
impl Flush for IdealCOTSender {
    type Error = IdealCOTError;

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

/// Message-based ideal COT receiver.
///
/// Wraps `ot-core`'s `IdealCOTReceiver` and receives `FlushMsg` from the
/// network.
pub struct IdealCOTReceiver {
    core: CoreReceiver,
}

impl COTReceiver<bool, Block> for IdealCOTReceiver {
    type Error = IdealCOTError;
    type Future = MaybeDone<COTReceiverOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        COTReceiver::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        COTReceiver::available(&self.core)
    }

    fn queue_recv_cot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_cot(choices).map_err(From::from)
    }
}

#[async_trait]
impl Flush for IdealCOTReceiver {
    type Error = IdealCOTError;

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

/// Ideal COT error.
#[derive(Debug, thiserror::Error)]
pub enum IdealCOTError {
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
    use mpz_ot_core::test::assert_cot;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;

    #[tokio::test]
    async fn test_ideal_cot() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta: Block = rng.random();

        let (mut sender, mut receiver) = ideal_cot(delta);
        let (mut ctx_s, mut ctx_r) = test_st_context(1024 * 1024);

        // Generate keys and choices
        let keys: Vec<Block> = (0..128).map(|_| rng.random()).collect();
        let choices: Vec<bool> = (0..128).map(|_| rng.random()).collect();

        // Queue operations
        let mut sender_out = sender.queue_send_cot(&keys).unwrap();
        let mut receiver_out = receiver.queue_recv_cot(&choices).unwrap();

        // Flush
        let (r1, r2) = futures::join!(sender.flush(&mut ctx_s), receiver.flush(&mut ctx_r));
        r1.unwrap();
        r2.unwrap();

        // Get outputs
        let _ = sender_out.try_recv().unwrap().unwrap();
        let receiver_output = receiver_out.try_recv().unwrap().unwrap();

        // Verify correctness
        assert_cot(delta, &choices, &keys, &receiver_output.msgs);
    }
}
