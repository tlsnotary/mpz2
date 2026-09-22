use std::{collections::VecDeque, sync::Arc};

use rand::{RngExt, SeedableRng};
use tokio::sync::{Mutex, OwnedMutexGuard};

use mpz_common::future::{MaybeDone, Sender as OutputSender, new_output};
use mpz_core::{
    Block,
    lpn::{LpnEncoder, LpnParameters, sample_error_indices},
    prg::Prg,
};

use crate::{
    TransferId,
    ferret::{
        FerretConfig, Init, ReceiverCheck, ReceiverExtend, SenderCheck, SenderExtend,
        config::CSP,
        mpcot::{MPCOTReceiver, MPCOTReceiverError, receiver_state as mpcot_state},
        spcot::{SPCOTReceiver, SPCOTReceiverError},
    },
    rcot::{RCOTReceiver, RCOTReceiverOutput},
};

type Error = ReceiverError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
struct Queued {
    count: usize,
    sender: OutputSender<RCOTReceiverOutput<bool, Block>>,
}

/// Ferret receiver.
#[derive(Debug)]
pub struct Receiver<COT> {
    cot: Arc<Mutex<COT>>,
    alloc: usize,
    queue: VecDeque<Queued>,
    transfer_id: TransferId,
    prg: Prg,
    config: FerretConfig,
    macs: Vec<Block>,
    choices: Vec<bool>,
    state: State,
    spcot: SPCOTReceiver,
}

impl<COT> Receiver<COT>
where
    COT: RCOTReceiver<bool, Block>,
{
    /// Creates a new receiver.
    pub fn new(seed: Block, config: FerretConfig, cot: COT) -> Self {
        Self {
            cot: Arc::new(Mutex::new(cot)),
            alloc: 0,
            queue: VecDeque::new(),
            transfer_id: TransferId::default(),
            prg: Prg::from_seed(seed),
            config,
            macs: Vec::new(),
            choices: Vec::new(),
            state: State::Init,
            spcot: SPCOTReceiver::new(),
        }
    }

    /// Returns a lock on the inner COT sender.
    pub fn acquire_cot(&self) -> OwnedMutexGuard<COT> {
        Mutex::try_lock_owned(self.cot.clone()).unwrap()
    }

    /// Returns `true` if the receiver wants to initialize.
    pub fn wants_init(&self) -> bool {
        matches!(self.state, State::Init)
    }

    /// Returns `true` if the receiver wants to bootstrap.
    pub fn wants_bootstrap(&self) -> bool {
        self.macs.len() < self.config.bootstrap_cost()
    }

    /// Returns `true` if the receiver wants to extend.
    pub fn wants_extend(&self) -> bool {
        self.available() < self.alloc
    }

    /// Initializes the receiver.
    pub fn initialize(&mut self) -> Result<Init> {
        let State::Init = self.state.take() else {
            return Err(ErrorRepr::State("not in initialize state".to_string()).into());
        };

        let seed = self.prg.random();

        self.state = State::Extend(Extend {
            public_prg: Prg::from_seed(seed),
        });

        Ok(Init { seed })
    }

    /// Allocates COTs for bootstrapping.
    pub fn alloc_bootstrap(&self) -> Result<()> {
        let missing = self.config.bootstrap_cost().saturating_sub(self.macs.len());
        self.cot
            .try_lock()
            .map_err(|_| ErrorRepr::MutexLocked)?
            .alloc(missing)
            .map_err(Error::bootstrap)?;

        Ok(())
    }

    /// Starts extension.
    pub fn start_extend(&mut self) -> Result<ReceiverExtend> {
        let State::Extend(Extend { mut public_prg }) = self.state.take() else {
            return Err(ErrorRepr::State("not in extend state".to_string()).into());
        };

        // If available COTs are insufficient, we bootstrap from the inner COT
        // instance.
        if self.wants_bootstrap() {
            let missing = self.config.bootstrap_cost() - self.macs.len();
            let RCOTReceiverOutput {
                msgs: macs,
                choices,
                ..
            } = self
                .cot
                .try_lock()
                .map_err(|_| ErrorRepr::MutexLocked)?
                .try_recv_rcot(missing)
                .map_err(|e| ErrorRepr::Bootstrap(Box::new(e)))?;

            self.macs.extend_from_slice(&macs);
            self.choices.extend_from_slice(&choices);
        }

        let missing = self.alloc.saturating_sub(self.available());
        let params = self.config.select_params(self.macs.len(), missing);

        let lpn_type = self.config.lpn_type();
        let err = sample_error_indices(&mut self.prg, lpn_type, params.n, params.t);

        let (mpcot, spcot_lengths, spcot_idxs) =
            MPCOTReceiver::new(public_prg.random(), lpn_type).start_extend(&err, params.n)?;

        let spcot_count: usize = spcot_lengths.iter().sum();
        let masks = &self.choices[self.choices.len() - spcot_count..];
        let derandomize = self.spcot.derandomize(&spcot_lengths, &spcot_idxs, masks)?;

        // Drop used COT choices.
        self.choices.truncate(self.choices.len() - spcot_count);

        self.state = State::Extending(Extending {
            public_prg,
            params,
            err,
            mpcot,
            spcot_count,
            spcot_lengths,
            spcot_idxs,
        });

        Ok(ReceiverExtend { derandomize })
    }

    /// Performs extension.
    ///
    /// # Arguments
    ///
    /// * `msg` - The sender's extend message.
    pub fn extend(&mut self, msg: SenderExtend) -> Result<ReceiverCheck> {
        let SenderExtend { ms, sums } = msg;

        let State::Extending(Extending {
            public_prg,
            params,
            err: e,
            mpcot,
            spcot_count,
            spcot_lengths,
            spcot_idxs,
        }) = self.state.take()
        else {
            return Err(ErrorRepr::State("not in extending state".to_string()).into());
        };

        let macs = &self.macs[self.macs.len() - spcot_count..];
        let ws = self
            .spcot
            .extend(&spcot_lengths, &spcot_idxs, macs, &ms, &sums)?;

        // Drop used COTs.
        self.macs.truncate(self.macs.len() - spcot_count);

        let r = mpcot.extend(ws)?;

        let macs = &self.macs[self.macs.len() - CSP..];
        let masks = &self.choices[self.choices.len() - CSP..];
        let derandomize = self.spcot.start_check(macs, masks)?;

        // Drop used COTs.
        self.macs.truncate(self.macs.len() - CSP);
        self.choices.truncate(self.choices.len() - CSP);

        self.state = State::Finish(Finish {
            public_prg,
            params,
            err: e,
            r,
        });

        Ok(ReceiverCheck { derandomize })
    }

    /// Finishes extension.
    ///
    /// # Arguments
    ///
    /// * `msg` - The sender's check message.
    pub fn finish_extend(&mut self, msg: SenderCheck) -> Result<()> {
        let SenderCheck { hashed_v } = msg;

        let State::Finish(Finish {
            mut public_prg,
            params,
            err,
            r,
        }) = self.state.take()
        else {
            return Err(ErrorRepr::State("not in finish state".to_string()).into());
        };

        self.spcot.check(hashed_v)?;

        let encoder = LpnEncoder::<10>::new(params.k as u32);
        let lpn_seed = public_prg.random();

        // Compute z = A * w + r.
        let w = &self.macs[self.macs.len() - params.k..];
        let mut z = r;
        encoder.compute(lpn_seed, &mut z, w);

        self.macs.truncate(self.macs.len() - params.k);

        // Compute x = A * u + e.
        let u: Vec<_> = self.choices[self.choices.len() - params.k..]
            .iter()
            .map(|x| if *x { Block::ONE } else { Block::ZERO })
            .collect();
        let mut x = vec![Block::ZERO; params.n];
        for &idx in &err {
            x[idx] = Block::ONE;
        }

        encoder.compute(lpn_seed, &mut x, &u);

        self.choices.truncate(self.choices.len() - params.k);

        let x: Vec<_> = x.iter().map(|x| x.lsb()).collect();

        self.macs.extend_from_slice(&z);
        self.choices.extend_from_slice(&x);

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
            let macs = self.macs.split_off(self.macs.len() - next.count);
            let choices = self.choices.split_off(self.choices.len() - next.count);

            next.sender.send(RCOTReceiverOutput {
                id,
                msgs: macs,
                choices,
            });
        }
    }
}

impl<COT> RCOTReceiver<bool, Block> for Receiver<COT>
where
    COT: RCOTReceiver<bool, Block>,
{
    type Error = ReceiverError;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<()> {
        self.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        if self.config.reserve_bootstrap() {
            self.macs.len().saturating_sub(self.config.bootstrap_cost())
        } else {
            self.macs.len()
        }
    }

    fn try_recv_rcot(&mut self, count: usize) -> Result<RCOTReceiverOutput<bool, Block>> {
        if self.available() < count {
            return Err(ErrorRepr::InsufficientCOTs {
                expected: count,
                actual: self.available(),
            }
            .into());
        }

        let choices = self.choices.split_off(self.choices.len() - count);
        let macs = self.macs.split_off(self.macs.len() - count);

        Ok(RCOTReceiverOutput {
            id: self.transfer_id.next(),
            choices,
            msgs: macs,
        })
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future> {
        if self.available() >= count {
            let output = self.try_recv_rcot(count)?;
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
    err: Vec<usize>,
    mpcot: MPCOTReceiver<mpcot_state::Extension>,
    spcot_count: usize,
    spcot_lengths: Vec<usize>,
    spcot_idxs: Vec<usize>,
}

struct Finish {
    public_prg: Prg,
    params: LpnParameters,
    err: Vec<usize>,
    r: Vec<Block>,
}

/// Ferret receiver error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ReceiverError(ErrorRepr);

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
    #[error("invalid state: {0}")]
    State(String),
    #[error("bootstrap COT mutex is still locked")]
    MutexLocked,
    #[error("bootstrap COT error: {0}")]
    Bootstrap(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("SPCOT receiver error: {0}")]
    Spcot(SPCOTReceiverError),
    #[error("MPCOT receiver error: {0}")]
    Mpcot(MPCOTReceiverError),
    #[error("insufficient COTs: expected {expected}, actual {actual}")]
    InsufficientCOTs { expected: usize, actual: usize },
}

impl From<ErrorRepr> for ReceiverError {
    fn from(repr: ErrorRepr) -> Self {
        Self(repr)
    }
}

impl From<SPCOTReceiverError> for ReceiverError {
    fn from(err: SPCOTReceiverError) -> Self {
        Self(ErrorRepr::Spcot(err))
    }
}

impl From<MPCOTReceiverError> for ReceiverError {
    fn from(err: MPCOTReceiverError) -> Self {
        Self(ErrorRepr::Mpcot(err))
    }
}
