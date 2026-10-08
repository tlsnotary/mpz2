use std::{collections::VecDeque, mem};

use crate::{
    TransferId,
    kos::{CSP, Check, Extend, SSP, SenderConfig, SenderError},
    rcot::{RCOTSender, RCOTSenderOutput},
};

use itybity::ToBits;
use mpz_common::future::{MaybeDone, Sender as OutputSender, new_output};
use mpz_core::{Block, prg::Prg};

use rand::{Rng as _, RngExt, SeedableRng, rng};

cfg_if::cfg_if! {
    if #[cfg(feature = "rayon")] {
        use itybity::ToParallelBits;
        use rayon::prelude::*;
    }
}

#[derive(Debug)]
struct Queued {
    count: usize,
    sender: OutputSender<RCOTSenderOutput<Block>>,
}

/// KOS15 sender.
#[derive(Debug)]
pub struct Sender<T: state::State = state::Initialized> {
    config: SenderConfig,
    alloc: usize,
    queue: VecDeque<Queued>,
    transfer_id: TransferId,
    delta: Block,
    state: T,
}

impl<T> Sender<T>
where
    T: state::State,
{
    /// Returns the Sender's configuration
    pub fn config(&self) -> &SenderConfig {
        &self.config
    }
}

impl Sender<state::Initialized> {
    /// Creates a new Sender
    ///
    /// # Arguments
    ///
    /// * `config` - Sender's configuration.
    /// * `delta` - Global COT correlation.
    pub fn new(config: SenderConfig, delta: Block) -> Self {
        Sender {
            config,
            // We need to extend SSP OTs for the consistency check.
            // Right now we only support one extension, so we just alloc
            // them here.
            alloc: SSP,
            transfer_id: TransferId::default(),
            queue: VecDeque::default(),
            delta,
            state: state::Initialized::default(),
        }
    }

    /// Complete the setup phase of the protocol.
    ///
    /// # Arguments
    ///
    /// * `seeds` - The rng seeds chosen during base OT
    pub fn setup(self, seeds: [Block; CSP]) -> Sender<state::Extension> {
        Sender {
            config: self.config,
            alloc: self.alloc,
            transfer_id: self.transfer_id,
            queue: self.queue,
            delta: self.delta,
            state: state::Extension {
                rngs: seeds.into_iter().map(Prg::from_seed).collect(),
                keys: Vec::default(),
                extended: false,
                unchecked_qs_trans: Vec::default(),
                unchecked_qs: vec![Vec::default(); CSP],
                chi: None,
            },
        }
    }
}

impl Sender<state::Extension> {
    /// Returns `true` if the sender wants to extend.
    pub fn wants_extend(&self) -> bool {
        self.alloc != 0
    }

    /// Returns `true` if the sender wants to run the consistency check.
    pub fn wants_check(&self) -> bool {
        self.alloc == 0 && !self.state.unchecked_qs.is_empty()
    }

    /// Perform the IKNP OT extension.
    ///
    /// # Arguments
    ///
    /// * `extend` - Extend message from the receiver.
    pub fn extend(&mut self, extend: Extend) -> Result<(), SenderError> {
        if self.state.extended {
            return Err(SenderError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        let Extend { count, us } = extend;

        let expected_count = self.config.batch_size().min(self.alloc);
        // Round up to a multiple of SSP, as per Figure 10:
        // "assume that s|l".
        let expected_count = (expected_count + (SSP - 1)) & !(SSP - 1);
        if count != expected_count {
            return Err(SenderError::CountMismatch {
                expected: expected_count,
                actual: count,
            });
        }

        const NROWS: usize = CSP;
        let row_width = count / 8;

        let mut qs = vec![0u8; NROWS * row_width];
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let iter = self.delta
                    .par_iter_lsb0()
                    .zip(self.state.rngs.par_iter_mut())
                    .zip(qs.par_chunks_exact_mut(row_width))
                    .zip(us.par_chunks_exact(row_width));
            } else {
                let iter = self.delta
                    .iter_lsb0()
                    .zip(self.state.rngs.iter_mut())
                    .zip(qs.chunks_exact_mut(row_width))
                    .zip(us.chunks_exact(row_width));
            }
        }

        // Figure 3, step 4.
        let zero = vec![0u8; row_width];
        iter.for_each(|(((b, rng), q), u)| {
            // Reuse `q` to avoid memory allocation for tⁱ_∆ᵢ
            rng.fill_bytes(q);
            // If `b` (i.e. ∆ᵢ) is true, xor `u` into `q`, otherwise xor 0 into
            // `q` (constant time).
            let u = if b { u } else { &zero };
            q.iter_mut().zip(u).for_each(|(q, u)| *q ^= u);
        });

        // Extend existing rows.
        for (existing_row, new_row) in self
            .state
            .unchecked_qs
            .iter_mut()
            .zip(qs.chunks_exact(qs.len() / NROWS))
        {
            let new_blocks: &[Block] =
                bytemuck::try_cast_slice(new_row).expect("row length is a multiple of Block size");
            existing_row.extend_from_slice(new_blocks);
        }

        matrix_transpose::transpose_bits(&mut qs, NROWS).expect("matrix is rectangular");

        let q_blocks: &[Block] =
            bytemuck::try_cast_slice(&qs).expect("qs length is a multiple of Block size");

        self.state.unchecked_qs_trans.extend(q_blocks.iter());

        self.alloc = self.alloc.saturating_sub(count);

        Ok(())
    }

    /// Starts the consistency check by sampling a random seed.
    pub fn check_start(&mut self) -> Block {
        let chi = rng().random::<Block>();
        self.state.chi = Some(chi);
        chi
    }

    /// Performs the consistency check for all outstanding OTS.
    ///
    /// See section 4 of the paper for more details.
    ///
    /// # Arguments
    ///
    /// * `receiver_check` - The receiver's consistency check message.
    pub fn check(&mut self, receiver_check: Check) -> Result<(), SenderError> {
        if !self.wants_check() {
            return Err(SenderError::InvalidState("not ready to check".to_string()));
        }
        let chi_seed = std::mem::take(&mut self.state.chi).ok_or(SenderError::ChiNotSet)?;

        // Make sure we have enough sacrificial OTs to perform the consistency
        // check.
        if self.state.unchecked_qs.len() < SSP {
            return Err(SenderError::InsufficientSetup {
                expected: SSP,
                actual: self.state.unchecked_qs.len(),
            });
        }

        let mut rng = Prg::from_seed(chi_seed);

        let unchecked_qs = std::mem::take(&mut self.state.unchecked_qs);

        // Figure 10, "Consistency check".
        let m = unchecked_qs[0].len() - 1;

        // Figure 10, "Consistency check", point 1.
        // Sample random weights.
        let chis: Vec<Block> = (0..m).map(|_| rng.random()).collect::<Vec<_>>();

        // Figure 10, "Consistency check", point 3.
        // Compute the random linear combinations.
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let iter = unchecked_qs.into_par_iter();
            } else {
                let iter = unchecked_qs.into_iter();
            }
        }

        // qᶦ for all i = 1, ..., k.
        let check_q = iter
            .map(|mut row| {
                let last = row.pop().expect("row is not empty");
                Block::inn_prdt_red(&row, &chis) ^ last
            })
            .collect::<Vec<_>>();

        let Check { x, t } = receiver_check;

        for ((bit, t), q) in self.delta.iter_lsb0().zip(t).zip(check_q) {
            let x = if bit { x } else { Block::ZERO };
            if q != t ^ x {
                return Err(SenderError::ConsistencyCheckFailed);
            }
        }

        // Figure 10, "Transpose and randomize".
        // The matrix was already transposed earlier.
        // We do not randomize to remove the leakage because this is an
        // implementation of COT **with leakage**.
        let mut unchecked_qs = std::mem::take(&mut self.state.unchecked_qs_trans);

        // Strip off the rows sacrificed for the consistency check.
        let nrows = unchecked_qs.len() - SSP;
        unchecked_qs.truncate(nrows);

        self.state.keys.extend_from_slice(&unchecked_qs);
        self.state.extended = true;

        // Resolve any queued transfers.
        if !self.queue.is_empty() {
            let mut i = 0;
            for Queued { count, sender } in mem::take(&mut self.queue) {
                let keys = self.state.keys[i..i + count].to_vec();
                i += count;
                sender.send(RCOTSenderOutput {
                    id: self.transfer_id.next(),
                    keys,
                });
            }

            self.state.keys.drain(..i);
        }

        Ok(())
    }
}

impl RCOTSender<Block> for Sender<state::Initialized> {
    type Error = SenderError;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.alloc += count;

        Ok(())
    }

    fn available(&self) -> usize {
        0
    }

    fn delta(&self) -> Block {
        self.delta
    }

    fn try_send_rcot(&mut self, _count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        Err(SenderError::InvalidState(
            "sender has not been setup yet".to_string(),
        ))
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        self.queue.push_back(Queued { count, sender });

        Ok(recv)
    }
}

impl RCOTSender<Block> for Sender<state::Extension> {
    type Error = SenderError;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if self.state.extended {
            return Err(SenderError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        self.alloc += count;

        Ok(())
    }

    fn available(&self) -> usize {
        self.state.keys.len()
    }

    fn delta(&self) -> Block {
        self.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        if self.available() < count {
            return Err(SenderError::InsufficientSetup {
                expected: count,
                actual: self.available(),
            });
        }

        let keys = self.state.keys.drain(..count).collect();

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
        } else if !self.state.extended {
            let (sender, recv) = new_output();

            self.queue.push_back(Queued { count, sender });

            Ok(recv)
        } else {
            Err(SenderError::InsufficientSetup {
                expected: count,
                actual: self.available(),
            })
        }
    }
}

/// The sender's state.
pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Extension {}
    }

    /// The sender's state.
    pub trait State: sealed::Sealed {}

    /// The sender's initial state.
    #[derive(Default)]
    pub struct Initialized {}

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The sender's state after the setup phase.
    ///
    /// In this state the sender performs OT extension (potentially multiple
    /// times). Also in this state the sender responds to OT requests.
    pub struct Extension {
        /// Receiver's rngs seeded from seeds obliviously received from base OT.
        pub(super) rngs: Vec<Prg>,
        /// Whether extension has occurred yet.
        ///
        /// This is to prevent the receiver from extending twice.
        pub(super) extended: bool,
        /// Sender's unchecked qs after transposing.
        pub(super) unchecked_qs_trans: Vec<Block>,
        /// Sender's unchecked qs before transposing.
        ///
        /// This is a row-major matrix which has [CSP] rows.
        pub(super) unchecked_qs: Vec<Vec<Block>>,
        /// Sender's keys.
        pub(super) keys: Vec<Block>,
        /// A seed for the random weights χ for the consistency check.
        pub(super) chi: Option<Block>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
