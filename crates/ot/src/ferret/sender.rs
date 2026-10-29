use async_trait::async_trait;
use mpz_common::{Context, Flush, future::MaybeDone};
use mpz_core::Block;
use mpz_ot_core::{
    ferret::{FerretConfig, Sender as Core, SenderError as CoreError},
    rcot::{RCOTSender, RCOTSenderOutput},
};
use serio::{SinkExt, stream::IoStreamExt};

type Error = SenderError;

/// Ferret sender.
#[derive(Debug)]
pub struct Sender<COT> {
    core: Core<COT>,
}

impl<COT> Sender<COT>
where
    COT: RCOTSender<Block>,
{
    /// Creates a new Sender.
    ///
    /// # Arguments
    ///
    /// * `config` - Sender's configuration.
    /// * `seed` - Sender's PRG seed.
    /// * `cot` - COT used for bootstrapping.
    pub fn new(config: FerretConfig, seed: Block, cot: COT) -> Self {
        Self {
            core: Core::new(seed, config, cot),
        }
    }
}

impl<COT> RCOTSender<Block> for Sender<COT>
where
    COT: RCOTSender<Block>,
{
    type Error = Error;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.core.alloc(count).map_err(Error::from)
    }

    fn available(&self) -> usize {
        self.core.available()
    }

    fn delta(&self) -> Block {
        self.core.delta()
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        self.core.try_send_rcot(count).map_err(Error::from)
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_rcot(count).map_err(Error::from)
    }
}

#[async_trait]
impl<COT> Flush for Sender<COT>
where
    COT: RCOTSender<Block> + Flush + Send,
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
            self.core.start_extend()?;
            let msg = ctx.io_mut().expect_next().await?;
            let msg = self.core.extend(msg)?;
            ctx.io_mut().send(msg).await?;
            let msg = ctx.io_mut().expect_next().await?;
            let msg = self.core.check(msg)?;
            ctx.io_mut().send(msg).await?;
            self.core.finish_extend()?;
        }

        Ok(())
    }
}

/// Ferret sender error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SenderError(#[from] ErrorRepr);

impl SenderError {
    fn bootstrap<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Bootstrap(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("ferret sender error: {0}")]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(CoreError),
    #[error("bootstrap COT error: {0}")]
    Bootstrap(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("io error: {0}")]
    Io(std::io::Error),
}

impl From<CoreError> for SenderError {
    fn from(e: CoreError) -> Self {
        Self(ErrorRepr::Core(e))
    }
}

impl From<std::io::Error> for SenderError {
    fn from(e: std::io::Error) -> Self {
        Self(ErrorRepr::Io(e))
    }
}
