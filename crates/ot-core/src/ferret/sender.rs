use std::{collections::VecDeque, sync::Arc};

use rand::{RngExt, SeedableRng};
use tokio::sync::{Mutex, OwnedMutexGuard};

use mpz_cointoss_core::{
    CointossError, Receiver as CointossReceiver, receiver_state as cointoss_state,
};
use mpz_common::future::{MaybeDone, Sender as OutputSender, new_output};
use mpz_core::{
    Block,
    lpn::{LpnEncoder, LpnParameters},
    prg::Prg,
};

use mpz_fields::{Field, gf2_128::Gf2_128};

#[cfg(feature = "emp")]
use crate::ferret::emp;

use crate::{
    TransferId,
    ferret::{
        FerretConfig, ReceiverCheck, ReceiverExtend, SenderCheck, SenderExtend,
        mpcot::{self, MPCOTError},
        spcot::{SPCOTSender, SPCOTSenderError},
        split_off_blocks,
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
    /// COT keys, stored as field elements for the SPCOT consistency check.
    /// Converted to blocks only when correlations leave through the RCOT
    /// interface.
    keys: Vec<Gf2_128>,
    /// Number of in-progress correlations at the tail of the buffer, not yet
    /// finalized by the current extension.
    pending: usize,
    state: State,
    spcot: SPCOTSender,
    /// All emp-only state; see [`emp::EmpSender`].
    #[cfg(feature = "emp")]
    pub(crate) emp: emp::EmpSender,
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
            pending: 0,
            state: State::Extend,
            spcot: SPCOTSender::new(delta),
            #[cfg(feature = "emp")]
            emp: emp::EmpSender::new(),
        }
    }

    /// Sets the session id for the compat derivations.
    #[cfg(feature = "emp")]
    pub fn set_sid(&mut self, sid: Block) {
        self.emp.sid = sid;
    }

    /// Returns a lock on the inner COT sender.
    pub fn acquire_cot(&self) -> OwnedMutexGuard<COT> {
        Mutex::try_lock_owned(self.cot.clone()).unwrap()
    }

    /// Returns `true` if the sender wants to bootstrap.
    pub fn wants_bootstrap(&self) -> bool {
        self.keys.len() < self.config.bootstrap_cost()
    }

    /// Returns `true` if the sender wants to extend.
    pub fn wants_extend(&self) -> bool {
        self.available() < self.alloc
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
        let State::Extend = self.state.take() else {
            return Err(ErrorRepr::State("not in extend state".to_string()).into());
        };

        // The previous round's refill trees are this round's bases.
        #[cfg(feature = "emp")]
        self.emp.begin_round(&mut self.keys);

        // If available COTs are insufficient, we bootstrap from the inner COT instance.
        if self.wants_bootstrap() {
            let missing = self.config.bootstrap_cost() - self.keys.len();
            let RCOTSenderOutput { keys, .. } = self
                .cot
                .try_lock()
                .map_err(|_| ErrorRepr::MutexLocked)?
                .try_send_rcot(missing)
                .map_err(|e| ErrorRepr::Bootstrap(Box::new(e)))?;

            self.keys.extend(keys.iter().map(|&key| Gf2_128::from(key)));
        }
        let missing = self.alloc.saturating_sub(self.available());
        let params = self.config.select_params(self.keys.len(), missing);

        let spcot_lengths = mpcot::spcot_lengths(params.t, params.n)?;

        self.state = State::Extending(Extending {
            params,
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
        let ReceiverExtend {
            derandomize,
            lpn_seed_commitment,
        } = msg;

        let State::Extending(Extending {
            params,
            spcot_lengths,
        }) = self.state.take()
        else {
            return Err(ErrorRepr::State("not in extending state".to_string()).into());
        };

        let spcot_count: usize = spcot_lengths.iter().sum();
        let plan = self.config.round_plan(params);
        debug_assert_eq!(
            plan.user_len + plan.refill_trees * (params.n / params.t),
            params.n
        );
        let cost = plan.cost;
        if self.keys.len() < cost {
            return Err(ErrorRepr::InsufficientCOTs {
                expected: cost,
                actual: self.keys.len(),
            }
            .into());
        }

        // Pop the COT keys consumed by this extension off the tail: the SPCOT
        // keys, the consistency check keys, and the LPN input. This frees the
        // tail of the keys buffer so the SPCOT vectors can be expanded
        // directly into their final place.
        let (spcot_keys, check_keys, lpn_keys) = plan.tail(spcot_count).split(&mut self.keys);

        // For regular indices, the MPCOT output is the concatenation of the
        // SPCOT vectors (Step 5 in Figure 7), which the SPCOT writes
        // directly into the tail of the keys buffer.
        let start = self.keys.len();
        self.keys.resize(start + params.n, Gf2_128::zero());
        self.pending = params.n;

        let cs = self.spcot.extend(
            &mut self.prg,
            &spcot_lengths,
            &spcot_keys,
            &derandomize.flip,
            &mut self.keys[start..],
        )?;

        // Contribute our share of the LPN seed coin-toss. The receiver is
        // committed to its share, so neither party can bias the seed towards
        // a weak LPN code.
        let (cointoss, lpn_seed_share) =
            CointossReceiver::new(vec![self.prg.random()]).reveal(lpn_seed_commitment)?;

        self.state = State::Check(Check {
            params,
            check_keys,
            lpn_keys,
            cointoss,
        });

        Ok(SenderExtend { cs, lpn_seed_share })
    }

    /// Performs the SPCOT consistency check.
    ///
    /// # Arguments
    ///
    /// * `msg` - Receiver check message.
    pub fn check(&mut self, msg: ReceiverCheck) -> Result<SenderCheck> {
        let ReceiverCheck {
            derandomize,
            chi_seed,
            lpn_seed_decommitment,
        } = msg;

        let State::Check(Check {
            params,
            check_keys,
            lpn_keys,
            cointoss,
        }) = self.state.take()
        else {
            return Err(ErrorRepr::State("not in check state".to_string()).into());
        };

        let lpn_seed_coin = cointoss.finalize(lpn_seed_decommitment)?;
        #[cfg(not(feature = "emp"))]
        let lpn_seed = lpn_seed_coin[0];
        #[cfg(feature = "emp")]
        let lpn_seed = {
            let _ = lpn_seed_coin;
            // From the session id.
            crate::ferret::emp::lpn_seed(self.emp.sid)
        };

        let vs = &self.keys[self.keys.len() - params.n..];
        let hashed_v = self
            .spcot
            .check(&check_keys, &derandomize.flip, vs, chi_seed)?;

        self.state = State::Finish(Finish {
            params,
            lpn_keys,
            lpn_seed,
        });

        Ok(SenderCheck { hashed_v })
    }

    /// Finishes the extension.
    pub fn finish_extend(&mut self) -> Result<()> {
        let State::Finish(Finish {
            params,
            lpn_keys,
            lpn_seed,
        }) = self.state.take()
        else {
            return Err(ErrorRepr::State("not in finish state".to_string()).into());
        };

        let encoder = LpnEncoder::<10>::new(params.k as u32);
        let lpn_seed = lpn_seed.to_bytes();

        // Compute y = A * v + s, in-place over the SPCOT vectors at the tail
        // of the keys buffer, which then directly hold the extended
        // correlations.
        let start = self.keys.len() - params.n;
        let y = &mut self.keys[start..];
        encoder.compute(
            lpn_seed,
            zerocopy::transmute_mut!(y),
            zerocopy::transmute_ref!(lpn_keys.as_slice()),
        );
        self.pending = 0;

        // The last `refill_trees` trees seed the next round: move their
        // results out of the output buffer.
        #[cfg(feature = "emp")]
        self.emp
            .take_refill(&mut self.keys, self.config.round_plan(params), params);

        let missing = self.alloc.saturating_sub(self.available());
        if missing == 0 {
            // We've finished extending.
            self.alloc = 0;
            self.process_queue();
        }

        self.state = State::Extend;

        Ok(())
    }

    fn process_queue(&mut self) {
        while let Some(next) = self.queue.pop_front() {
            if self.available() < next.count {
                self.queue.push_front(next);
                return;
            }

            let id = self.transfer_id.next();
            let keys = split_off_blocks(&mut self.keys, next.count);

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
        let len = self.keys.len() - self.pending;
        len.saturating_sub(self.config.reserve())
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

        Ok(RCOTSenderOutput {
            id: self.transfer_id.next(),
            keys: split_off_blocks(&mut self.keys, count),
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
    Extend,
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

struct Extending {
    params: LpnParameters,
    spcot_lengths: Vec<usize>,
}

struct Check {
    params: LpnParameters,
    check_keys: Vec<Gf2_128>,
    lpn_keys: Vec<Gf2_128>,
    cointoss: CointossReceiver<cointoss_state::Received>,
}

struct Finish {
    params: LpnParameters,
    lpn_keys: Vec<Gf2_128>,
    lpn_seed: Block,
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
enum ErrorRepr {
    #[error("ferret sender error: invalid state: {0}")]
    State(String),
    #[error("ferret sender error: bootstrap COT mutex is still locked")]
    MutexLocked,
    #[error("ferret sender error: bootstrap COT error: {0}")]
    Bootstrap(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    Spcot(SPCOTSenderError),
    #[error(transparent)]
    Mpcot(MPCOTError),
    #[error("ferret sender error: LPN seed coin-toss error: {0}")]
    Cointoss(CointossError),
    #[error("ferret sender error: insufficient COTs: expected {expected}, actual {actual}")]
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

impl From<MPCOTError> for SenderError {
    fn from(e: MPCOTError) -> Self {
        Self(ErrorRepr::Mpcot(e))
    }
}

impl From<CointossError> for SenderError {
    fn from(e: CointossError) -> Self {
        Self(ErrorRepr::Cointoss(e))
    }
}
