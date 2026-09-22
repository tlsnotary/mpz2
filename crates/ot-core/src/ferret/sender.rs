use std::{collections::VecDeque, sync::Arc};

use rand::{RngExt, SeedableRng};
use tokio::sync::{Mutex, OwnedMutexGuard};

use mpz_common::future::{MaybeDone, Sender as OutputSender, new_output};
use mpz_core::{
    Block,
    lpn::{LpnEncoder, LpnParameters},
    prg::Prg,
};

use crate::{
    TransferId,
    ferret::{
        FerretConfig, Init, ReceiverCheck, ReceiverExtend, SenderCheck, SenderExtend,
        config::CSP,
        mpcot::{MPCOTSender, MPCOTSenderError, sender_state as mpcot_state},
        spcot::{SPCOTSender, SPCOTSenderError},
    },
    rcot::{RCOTSender, RCOTSenderOutput},
};

type Error = SenderError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
struct Queued {
    count: usize,
    sender: OutputSender<RCOTSenderOutput<Block>>,
}

/// Ferret sender.
#[derive(Debug)]
pub struct Sender<COT> {
    cot: Arc<Mutex<COT>>,
    alloc: usize,
    queue: VecDeque<Queued>,
    transfer_id: TransferId,
    prg: Prg,
    delta: Block,
    config: FerretConfig,
    keys: Vec<Block>,
    state: State,
    spcot: SPCOTSender,
}

impl<COT> Sender<COT>
where
    COT: RCOTSender<Block>,
{
    /// Creates a new sender.
    pub fn new(seed: Block, config: FerretConfig, cot: COT) -> Self {
        let delta = cot.delta();
        Self {
            cot: Arc::new(Mutex::new(cot)),
            alloc: 0,
            queue: VecDeque::new(),
            transfer_id: TransferId::default(),
            prg: Prg::from_seed(seed),
            delta,
            config,
            keys: Vec::new(),
            state: State::Init,
            spcot: SPCOTSender::new(delta),
        }
    }

    /// Returns a lock on the inner COT sender.
    pub fn acquire_cot(&self) -> OwnedMutexGuard<COT> {
        Mutex::try_lock_owned(self.cot.clone()).unwrap()
    }

    /// Returns `true` if the sender wants to initialize.
    pub fn wants_init(&self) -> bool {
        matches!(self.state, State::Init)
    }

    /// Returns `true` if the sender wants to bootstrap.
    pub fn wants_bootstrap(&self) -> bool {
        self.keys.len() < self.config.bootstrap_cost()
    }

    /// Returns `true` if the sender wants to extend.
    pub fn wants_extend(&self) -> bool {
        self.available() < self.alloc
    }

    /// Initializes the sender, receiving message from the receiver.
    pub fn initialize(&mut self, init: Init) -> Result<()> {
        let State::Init = self.state.take() else {
            return Err(ErrorRepr::State("not in initialize state".to_string()).into());
        };

        let Init { seed } = init;

        self.state = State::Extend(Extend {
            public_prg: Prg::from_seed(seed),
        });

        Ok(())
    }

    /// Allocates COTs for bootstrapping.
    pub fn alloc_bootstrap(&self) -> Result<()> {
        let missing = self.config.bootstrap_cost().saturating_sub(self.keys.len());
        self.cot
            .try_lock()
            .map_err(|_| ErrorRepr::MutexLocked)?
            .alloc(missing)
            .map_err(Error::bootstrap)?;

        Ok(())
    }

    /// Starts extension.
    pub fn start_extend(&mut self) -> Result<()> {
        let State::Extend(Extend { mut public_prg }) = self.state.take() else {
            return Err(ErrorRepr::State("not in extend state".to_string()).into());
        };

        // If available COTs are insufficient, we bootstrap from the inner COT
        // instance.
        if self.wants_bootstrap() {
            let missing = self.config.bootstrap_cost() - self.keys.len();
            let RCOTSenderOutput { keys, .. } = self
                .cot
                .try_lock()
                .map_err(|_| ErrorRepr::MutexLocked)?
                .try_send_rcot(missing)
                .map_err(|e| ErrorRepr::Bootstrap(Box::new(e)))?;

            self.keys.extend_from_slice(&keys);
        }
        let missing = self.alloc.saturating_sub(self.available());
        let params = self.config.select_params(self.keys.len(), missing);

        let (mpcot, spcot_lengths) = MPCOTSender::new(public_prg.random(), self.config.lpn_type())
            .start_extend(params.t, params.n)?;

        self.state = State::Extending(Extending {
            public_prg,
            params,
            mpcot,
            spcot_lengths,
        });

        Ok(())
    }

    /// Performs extension.
    ///
    /// # Arguments
    ///
    /// * `msg` - Receiver extend message.
    pub fn extend(&mut self, msg: ReceiverExtend) -> Result<SenderExtend> {
        let ReceiverExtend { derandomize } = msg;

        let State::Extending(Extending {
            public_prg,
            params,
            mpcot,
            spcot_lengths,
        }) = self.state.take()
        else {
            return Err(ErrorRepr::State("not in extending state".to_string()).into());
        };

        let spcot_count: usize = spcot_lengths.iter().sum();
        let spcot_keys = &self.keys[self.keys.len() - spcot_count..];

        let (vs, ms, sums) =
            self.spcot
                .extend(&mut self.prg, &spcot_lengths, spcot_keys, &derandomize.flip)?;

        // Drop used keys.
        self.keys.truncate(self.keys.len() - spcot_count);

        let s = mpcot.extend(vs)?;

        self.state = State::Check(Check {
            public_prg,
            params,
            s,
        });

        Ok(SenderExtend { ms, sums })
    }

    /// Performs the SPCOT consistency check.
    ///
    /// # Arguments
    ///
    /// * `msg` - Receiver check message.
    pub fn check(&mut self, msg: ReceiverCheck) -> Result<SenderCheck> {
        let ReceiverCheck { derandomize } = msg;

        let State::Check(Check {
            public_prg,
            params,
            s,
        }) = self.state.take()
        else {
            return Err(ErrorRepr::State("not in check state".to_string()).into());
        };

        let check_keys = &self.keys[self.keys.len() - CSP..];
        let hashed_v = self.spcot.check(check_keys, &derandomize.flip)?;

        // Drop used keys.
        self.keys.truncate(self.keys.len() - CSP);

        self.state = State::Finish(Finish {
            public_prg,
            params,
            s,
        });

        Ok(SenderCheck { hashed_v })
    }

    /// Finishes the extension.
    pub fn finish_extend(&mut self) -> Result<()> {
        let State::Finish(Finish {
            mut public_prg,
            params,
            s,
        }) = self.state.take()
        else {
            return Err(ErrorRepr::State("not in finish state".to_string()).into());
        };

        let encoder = LpnEncoder::<10>::new(params.k as u32);
        let lpn_seed = public_prg.random();

        // Compute y = A * v + s
        let v = &self.keys[self.keys.len() - params.k..];
        let mut y = s;
        encoder.compute(lpn_seed, &mut y, v);

        self.keys.truncate(self.keys.len() - params.k);
        self.keys.extend_from_slice(&y);

        let missing = self.alloc.saturating_sub(self.available());
        if missing == 0 {
            // We've finished extending.
            self.alloc = 0;
            self.process_queue();
        }

        self.state = State::Extend(Extend { public_prg });

        Ok(())
    }

    fn process_queue(&mut self) {
        while let Some(next) = self.queue.pop_front() {
            if self.available() < next.count {
                self.queue.push_front(next);
                return;
            }

            let id = self.transfer_id.next();
            let keys = self.keys.split_off(self.keys.len() - next.count);

            next.sender.send(RCOTSenderOutput { id, keys });
        }
    }
}

impl<COT> RCOTSender<Block> for Sender<COT>
where
    COT: RCOTSender<Block>,
{
    type Error = SenderError;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<()> {
        self.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        if self.config.reserve_bootstrap() {
            self.keys.len().saturating_sub(self.config.bootstrap_cost())
        } else {
            self.keys.len()
        }
    }

    fn delta(&self) -> Block {
        self.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        if self.available() < count {
            return Err(ErrorRepr::InsufficientCOTs {
                expected: count,
                actual: self.available(),
            }
            .into());
        }

        let keys = self.keys.split_off(self.keys.len() - count);

        Ok(RCOTSenderOutput {
            id: self.transfer_id.next(),
            keys,
        })
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.available() >= count {
            let output = self.try_send_rcot(count)?;
            let (sender, recv) = new_output();
            sender.send(output);

            Ok(recv)
        } else {
            let (sender, recv) = new_output();

            self.queue.push_back(Queued { count, sender });

            Ok(recv)
        }
    }
}

enum State {
    Init,
    Extend(Extend),
    Extending(Extending),
    Check(Check),
    Finish(Finish),
    Error,
}

opaque_debug::implement!(State);

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

struct Extend {
    public_prg: Prg,
}

struct Extending {
    public_prg: Prg,
    params: LpnParameters,
    mpcot: MPCOTSender<mpcot_state::Extension>,
    spcot_lengths: Vec<usize>,
}

struct Check {
    public_prg: Prg,
    params: LpnParameters,
    s: Vec<Block>,
}

struct Finish {
    public_prg: Prg,
    params: LpnParameters,
    s: Vec<Block>,
}

/// Ferret sender error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SenderError(ErrorRepr);

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
    #[error("invalid state: {0}")]
    State(String),
    #[error("bootstrap COT mutex is still locked")]
    MutexLocked,
    #[error("bootstrap COT error: {0}")]
    Bootstrap(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("SPCOT sender error: {0}")]
    Spcot(SPCOTSenderError),
    #[error("MPCOT sender error: {0}")]
    Mpcot(MPCOTSenderError),
    #[error("insufficient COTs: expected {expected}, actual {actual}")]
    InsufficientCOTs { expected: usize, actual: usize },
}

impl From<ErrorRepr> for SenderError {
    fn from(repr: ErrorRepr) -> Self {
        Self(repr)
    }
}

impl From<SPCOTSenderError> for SenderError {
    fn from(e: SPCOTSenderError) -> Self {
        Self(ErrorRepr::Spcot(e))
    }
}

impl From<MPCOTSenderError> for SenderError {
    fn from(e: MPCOTSenderError) -> Self {
        Self(ErrorRepr::Mpcot(e))
    }
}
