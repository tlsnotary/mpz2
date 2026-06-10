use async_trait::async_trait;
use serio::{SinkExt, stream::IoStreamExt};

use mpz_common::{Context, Flush, future::MaybeDone};
use mpz_core::Block;
use mpz_ot_core::{
    ferret::{FerretConfig, Receiver as Core, ReceiverError as CoreError},
    rcot::{RCOTReceiver, RCOTReceiverOutput},
};

type Error = ReceiverError;

/// Ferret receiver.
#[derive(Debug)]
pub struct Receiver<COT> {
    core: Core<COT>,
}

impl<COT> Receiver<COT>
where
    COT: RCOTReceiver<bool, Block>,
{
    /// Creates a new Receiver.
    ///
    /// # Arguments
    ///
    /// * `config` - Receiver's configuration.
    /// * `seed` - Receiver's PRG seed.
    /// * `cot` - COT used for bootstrapping.
    pub fn new(config: FerretConfig, seed: Block, cot: COT) -> Self {
        Self {
            core: Core::new(seed, config, cot),
        }
    }
}

impl<COT> RCOTReceiver<bool, Block> for Receiver<COT>
where
    COT: RCOTReceiver<bool, Block>,
{
    type Error = Error;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.core.alloc(count).map_err(Error::from)
    }

    fn available(&self) -> usize {
        self.core.available()
    }

    fn try_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        self.core.try_recv_rcot(count).map_err(Error::from)
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_rcot(count).map_err(Error::from)
    }
}

#[async_trait]
impl<COT> Flush for Receiver<COT>
where
    COT: RCOTReceiver<bool, Block> + Flush + Send,
{
    type Error = Error;

    fn wants_flush(&self) -> bool {
        self.core.wants_extend()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.wants_bootstrap() {
            self.core.alloc_bootstrap()?;
            self.core
                .acquire_cot()
                .flush(ctx)
                .await
                .map_err(Error::bootstrap)?;
        }

        while self.core.wants_extend() {
            let msg = self.core.start_extend()?;
            ctx.io_mut().send(msg).await?;
            let msg = ctx.io_mut().expect_next().await?;
            let msg = self.core.extend(msg)?;
            ctx.io_mut().send(msg).await?;
            let msg = ctx.io_mut().expect_next().await?;
            self.core.finish_extend(msg)?;
        }

        Ok(())
    }
}

/// Ferret receiver error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ReceiverError(#[from] ErrorRepr);

impl ReceiverError {
    fn bootstrap<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Bootstrap(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("ferret receiver error: {0}")]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(CoreError),
    #[error("bootstrap COT error: {0}")]
    Bootstrap(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("io error: {0}")]
    Io(std::io::Error),
}

impl From<CoreError> for ReceiverError {
    fn from(e: CoreError) -> Self {
        Self(ErrorRepr::Core(e))
    }
}

impl From<std::io::Error> for ReceiverError {
    fn from(e: std::io::Error) -> Self {
        Self(ErrorRepr::Io(e))
    }
}
