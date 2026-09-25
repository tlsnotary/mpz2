use async_trait::async_trait;
use itybity::IntoBits;
use mpz_common::{Context, ContextError, Flush, future::MaybeDone};
use mpz_core::Block;
use mpz_ot_core::{
    kos::{Sender as Core, SenderConfig, SenderError as CoreError, sender_state as state},
    ot::{OTReceiver, OTReceiverOutput},
    rcot::{RCOTSender, RCOTSenderOutput},
};
use serio::{SinkExt, stream::IoStreamExt as _};

type Error = SenderError;

#[derive(Debug)]
enum State<BaseOT> {
    Initialized {
        base_ot: BaseOT,
        sender: Core<state::Initialized>,
    },
    Extension(Core<state::Extension>),
    Error,
}

impl<BaseOT> State<BaseOT> {
    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Error)
    }
}

/// KOS sender.
#[derive(Debug)]
pub struct Sender<BaseOT> {
    state: State<BaseOT>,
}

impl<BaseOT> Sender<BaseOT> {
    /// Creates a new Sender
    ///
    /// # Arguments
    ///
    /// * `config` - The Sender's configuration.
    /// * `delta` - Global COT correlation.
    /// * `instance_id` - Domain separator; must match the paired receiver and
    ///   differ across instances that reuse `delta`.
    /// * `base_ot` - Base OT.
    pub fn new(config: SenderConfig, delta: Block, instance_id: Block, base_ot: BaseOT) -> Self {
        Self {
            state: State::Initialized {
                base_ot,
                sender: Core::new(config, delta, instance_id),
            },
        }
    }
}

impl<BaseOT> RCOTSender<Block> for Sender<BaseOT> {
    type Error = Error;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        match &mut self.state {
            State::Initialized { sender, .. } => sender.alloc(count).map_err(Error::from),
            State::Extension(sender) => sender.alloc(count).map_err(Error::from),
            State::Error => Err(Error::state("cannot allocate, sender in error state")),
        }
    }

    fn available(&self) -> usize {
        match &self.state {
            State::Initialized { .. } | State::Error => 0,
            State::Extension(sender) => sender.available(),
        }
    }

    fn delta(&self) -> Block {
        match &self.state {
            State::Initialized { sender, .. } => sender.delta(),
            State::Extension(sender) => sender.delta(),
            State::Error => panic!("sender left in error state"),
        }
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        match &mut self.state {
            State::Initialized { sender, .. } => sender.try_send_rcot(count).map_err(Error::from),
            State::Extension(sender) => sender.try_send_rcot(count).map_err(Error::from),
            State::Error => Err(Error::state("cannot send, sender in error state")),
        }
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        match &mut self.state {
            State::Initialized { sender, .. } => sender.queue_send_rcot(count).map_err(Error::from),
            State::Extension(sender) => sender.queue_send_rcot(count).map_err(Error::from),
            State::Error => Err(Error::state("cannot queue, sender in error state")),
        }
    }
}

#[async_trait]
impl<BaseOT> Flush for Sender<BaseOT>
where
    BaseOT: OTReceiver<bool, Block> + Flush + Send,
    BaseOT::Future: Send,
{
    type Error = Error;

    fn wants_flush(&self) -> bool {
        match &self.state {
            State::Initialized { .. } => true,
            State::Extension(sender) => sender.wants_extend(),
            State::Error => false,
        }
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        let mut sender = match self.state.take() {
            State::Initialized {
                mut base_ot,
                sender,
            } => {
                let choices = sender.delta().into_lsb0_vec();
                let seeds = base_ot.queue_recv_ot(&choices).map_err(Error::base_ot)?;
                base_ot.flush(ctx).await.map_err(Error::base_ot)?;

                let OTReceiverOutput { msgs: seeds, .. } = seeds.await.map_err(Error::base_ot)?;

                let seeds = seeds.try_into().expect("seeds should be 128 long");

                sender.setup(seeds)
            }
            State::Extension(sender) => sender,
            State::Error => return Err(Error::state("can not flush, sender in error state")),
        };

        if !sender.wants_extend() {
            self.state = State::Extension(sender);
            return Ok(());
        }

        while sender.wants_extend() {
            let extend = ctx.io_mut().expect_next().await?;
            sender.extend(extend)?;
        }

        let seed = sender.check_start();
        ctx.io_mut().send(seed).await?;

        let receiver_check = ctx.io_mut().expect_next().await?;

        sender.check(receiver_check)?;

        self.state = State::Extension(sender);

        Ok(())
    }
}

/// Error for [`Sender`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SenderError(#[from] ErrorRepr);

impl SenderError {
    fn base_ot<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::BaseOT(err.into()))
    }

    fn state(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::State(msg.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("base OT error: {0}")]
    BaseOT(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("state error: {0}")]
    State(String),
    #[error("context error: {0}")]
    Context(#[from] ContextError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CoreError> for SenderError {
    fn from(err: CoreError) -> Self {
        Self(ErrorRepr::Core(err))
    }
}

impl From<ContextError> for SenderError {
    fn from(err: ContextError) -> Self {
        Self(ErrorRepr::Context(err))
    }
}

impl From<std::io::Error> for SenderError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}
