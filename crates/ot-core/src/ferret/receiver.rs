use std::{collections::VecDeque, sync::Arc};

use rand::{RngExt, SeedableRng};
use tokio::sync::{Mutex, OwnedMutexGuard};

use mpz_cointoss_core::{CointossError, Sender as CointossSender, sender_state as cointoss_state};
use mpz_common::future::{MaybeDone, Sender as OutputSender, new_output};
use mpz_core::{
    Block,
    lpn::{LpnEncoder, LpnParameters},
    prg::Prg,
};

use mpz_fields::{Field, gf2_128::Gf2_128};

#[cfg(not(feature = "emp"))]
use mpz_core::lpn::sample_error_indices;

#[cfg(feature = "emp")]
use crate::ferret::emp;

use crate::{
    TransferId,
    ferret::{
        FerretConfig, ReceiverCheck, ReceiverExtend, SenderCheck, SenderExtend,
        mpcot::{self, MPCOTError},
        spcot::{CheckStart, SPCOTReceiver, SPCOTReceiverError},
        split_off_blocks,
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
    /// COT MACs, stored as field elements for the SPCOT consistency check.
    /// Converted to blocks only when correlations leave through the RCOT
    /// interface.
    macs: Vec<Gf2_128>,
    /// Number of in-progress correlations at the tail of the buffer, not yet
    /// finalized by the current extension.
    pending: usize,
    choices: Vec<bool>,
    state: State,
    spcot: SPCOTReceiver,
    /// All emp-only state; see [`emp::EmpReceiver`].
    #[cfg(feature = "emp")]
    pub(crate) emp: emp::EmpReceiver,
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
            pending: 0,
            state: State::Extend,
            spcot: SPCOTReceiver::new(),
            #[cfg(feature = "emp")]
            emp: emp::EmpReceiver::new(),
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

    /// Returns `true` if the receiver wants to bootstrap.
    pub fn wants_bootstrap(&self) -> bool {
        self.macs.len() < self.config.bootstrap_cost()
    }

    /// Returns `true` if the receiver wants to extend.
    pub fn wants_extend(&self) -> bool {
        self.available() < self.alloc
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
        let State::Extend = self.state.take() else {
            return Err(ErrorRepr::State("not in extend state".to_string()).into());
        };

        // The previous round's refill trees are this round's bases.
        #[cfg(feature = "emp")]
        self.emp.begin_round(&mut self.macs, &mut self.choices);

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

            self.macs.extend(macs.iter().map(|&mac| Gf2_128::from(mac)));
            self.choices.extend_from_slice(&choices);
        }

        let missing = self.alloc.saturating_sub(self.available());
        let params = self.config.select_params(self.macs.len(), missing);

        let spcot_lengths = mpcot::spcot_lengths(params.t, params.n)?;
        let spcot_count: usize = spcot_lengths.iter().sum();
        let masks = &self.choices[self.choices.len() - spcot_count..];

        // From the cGGM-correction choices, so the sender's derandomization
        // is the identity.
        #[cfg(feature = "emp")]
        let err = mpcot::spcot_queries_from_choices(masks, &spcot_lengths, params.n);
        #[cfg(not(feature = "emp"))]
        let err = sample_error_indices(&mut self.prg, params.n, params.t);

        let (_, spcot_idxs) = mpcot::spcot_queries(&err, params.n)?;
        let derandomize = self.spcot.derandomize(&spcot_lengths, &spcot_idxs, masks)?;

        // Drop used COT choices.
        self.choices.truncate(self.choices.len() - spcot_count);

        // Commit to our share of the LPN seed coin-toss. The sender
        // contributes its share before we decommit, so neither party can
        // bias the seed towards a weak LPN code.
        let (cointoss, lpn_seed_commitment) = CointossSender::new(vec![self.prg.random()]).send();

        self.state = State::Extending(Extending {
            params,
            err,
            spcot_lengths,
            spcot_idxs,
            cointoss,
        });

        Ok(ReceiverExtend {
            derandomize,
            lpn_seed_commitment,
        })
    }

    /// Performs extension.
    ///
    /// # Arguments
    ///
    /// * `msg` - The sender's extend message.
    pub fn extend(&mut self, msg: SenderExtend) -> Result<ReceiverCheck> {
        let SenderExtend { cs, lpn_seed_share } = msg;

        let State::Extending(Extending {
            params,
            err,
            spcot_lengths,
            spcot_idxs,
            cointoss,
        }) = self.state.take()
        else {
            return Err(ErrorRepr::State("not in extending state".to_string()).into());
        };

        let (lpn_seeds, cointoss) = cointoss.receive(lpn_seed_share)?;
        #[cfg(not(feature = "emp"))]
        let lpn_seed = lpn_seeds[0];
        #[cfg(feature = "emp")]
        let lpn_seed = {
            let _ = lpn_seeds;
            // From the session id.
            crate::ferret::emp::lpn_seed(self.emp.sid)
        };
        let lpn_seed_decommitment = cointoss.finalize();

        let spcot_count: usize = spcot_lengths.iter().sum();
        let plan = self.config.round_plan(params);
        debug_assert_eq!(
            plan.user_len + plan.refill_trees * (params.n / params.t),
            params.n
        );
        let cost = plan.cost;
        if self.macs.len() < cost {
            return Err(ErrorRepr::InsufficientCOTs {
                expected: cost,
                actual: self.macs.len(),
            }
            .into());
        }

        // Pop the COT MACs consumed by this extension off the tail: the SPCOT
        // MACs, the consistency check MACs, and the LPN input. This frees the
        // tail of the MACs buffer so the SPCOT vectors can be expanded
        // directly into their final place.
        let tail = plan.tail(spcot_count);
        let (spcot_macs, check_macs, lpn_macs) = tail.split(&mut self.macs);
        let check_masks = tail.take_check_masks(&mut self.choices);

        // For regular indices, the MPCOT output is the concatenation of the
        // SPCOT vectors (Step 5 in Figure 7), which the SPCOT writes
        // directly into the tail of the MACs buffer.
        let start = self.macs.len();
        self.macs.resize(start + params.n, Gf2_128::zero());
        self.pending = params.n;

        self.spcot.extend(
            &spcot_lengths,
            &spcot_idxs,
            &spcot_macs,
            &cs,
            &mut self.macs[start..],
        )?;

        let CheckStart {
            derandomize,
            chi_seed,
        } = self.spcot.start_check(
            &mut self.prg,
            &check_macs,
            &check_masks,
            &self.macs[start..],
        )?;

        self.state = State::Finish(Finish {
            params,
            err,
            lpn_macs,
            lpn_seed,
        });

        Ok(ReceiverCheck {
            derandomize,
            chi_seed,
            lpn_seed_decommitment,
        })
    }

    /// Finishes extension.
    ///
    /// # Arguments
    ///
    /// * `msg` - The sender's check message.
    pub fn finish_extend(&mut self, msg: SenderCheck) -> Result<()> {
        let SenderCheck { hashed_v } = msg;

        let State::Finish(Finish {
            params,
            err,
            lpn_macs,
            lpn_seed,
        }) = self.state.take()
        else {
            return Err(ErrorRepr::State("not in finish state".to_string()).into());
        };

        self.spcot.check(hashed_v)?;

        let encoder = LpnEncoder::<10>::new(params.k as u32);
        let lpn_seed = lpn_seed.to_bytes();

        // Pack the LPN choice bits and the error bits.
        let choices = &self.choices[self.choices.len() - params.k..];
        let mut u = vec![0u8; params.k.div_ceil(8)];
        for (byte, bits) in u.iter_mut().zip(choices.chunks(8)) {
            for (i, &bit) in bits.iter().enumerate() {
                *byte |= (bit as u8) << i;
            }
        }

        let mut x = vec![0u8; params.n.div_ceil(8)];
        for &idx in &err {
            x[idx / 8] |= 1 << (idx % 8);
        }

        // Compute z = A * w + r and x = A * u + e in one pass, the former
        // in-place over the SPCOT vectors at the tail of the MACs buffer,
        // which then directly hold the extended correlations.
        let start = self.macs.len() - params.n;
        let z = &mut self.macs[start..];
        encoder.compute_with_bits(
            lpn_seed,
            zerocopy::transmute_mut!(z),
            &mut x,
            zerocopy::transmute_ref!(lpn_macs.as_slice()),
            &u,
        );
        self.pending = 0;

        self.choices.truncate(self.choices.len() - params.k);

        self.choices.reserve(params.n);
        let mut remaining = params.n;
        for &byte in &x {
            for i in 0..remaining.min(8) {
                self.choices.push((byte >> i) & 1 == 1);
            }
            remaining -= remaining.min(8);
        }

        // The last `refill_trees` trees seed the next round: move their MACs
        // and choices out of the output buffers.
        #[cfg(feature = "emp")]
        self.emp.take_refill(
            &mut self.macs,
            &mut self.choices,
            self.config.round_plan(params),
            params,
        );

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
            let macs = split_off_blocks(&mut self.macs, next.count);
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
        let len = self.macs.len() - self.pending;
        len.saturating_sub(self.config.reserve())
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
        let macs = split_off_blocks(&mut self.macs, count);

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
    Extend,
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

struct Extending {
    params: LpnParameters,
    err: Vec<usize>,
    spcot_lengths: Vec<usize>,
    spcot_idxs: Vec<usize>,
    cointoss: CointossSender<cointoss_state::Committed>,
}

struct Finish {
    params: LpnParameters,
    err: Vec<usize>,
    lpn_macs: Vec<Gf2_128>,
    lpn_seed: Block,
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
enum ErrorRepr {
    #[error("ferret receiver error: invalid state: {0}")]
    State(String),
    #[error("ferret receiver error: bootstrap COT mutex is still locked")]
    MutexLocked,
    #[error("ferret receiver error: bootstrap COT error: {0}")]
    Bootstrap(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    Spcot(SPCOTReceiverError),
    #[error(transparent)]
    Mpcot(MPCOTError),
    #[error("ferret receiver error: LPN seed coin-toss error: {0}")]
    Cointoss(CointossError),
    #[error("ferret receiver error: insufficient COTs: expected {expected}, actual {actual}")]
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

impl From<MPCOTError> for ReceiverError {
    fn from(err: MPCOTError) -> Self {
        Self(ErrorRepr::Mpcot(err))
    }
}

impl From<CointossError> for ReceiverError {
    fn from(err: CointossError) -> Self {
        Self(ErrorRepr::Cointoss(err))
    }
}
