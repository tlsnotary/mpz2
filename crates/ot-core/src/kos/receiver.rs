use std::{collections::VecDeque, mem};

use crate::{
    TransferId,
    kos::{CSP, Check, Extend, ReceiverConfig, ReceiverError, SSP},
    rcot::{RCOTReceiver, RCOTReceiverOutput},
};

use itybity::{BitLength, FromBitIterator, IntoBitIterator, IntoBits};
use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_core::{Block, prg::Prg};

use rand::{Rng as _, RngExt, SeedableRng};

#[cfg(feature = "rayon")]
use rayon::prelude::*;

#[derive(Debug)]
struct Queued {
    count: usize,
    sender: Sender<RCOTReceiverOutput<bool, Block>>,
}

/// KOS15 receiver.
#[derive(Debug, Default)]
pub struct Receiver<T: state::State = state::Initialized> {
    config: ReceiverConfig,
    alloc: usize,
    transfer_id: TransferId,
    queue: VecDeque<Queued>,
    state: T,
}

impl<T> Receiver<T>
where
    T: state::State,
{
    /// Returns the Receiver's configuration
    pub fn config(&self) -> &ReceiverConfig {
        &self.config
    }
}

impl Receiver {
    /// Creates a new Receiver
    ///
    /// # Arguments
    ///
    /// * `config` - The Receiver's configuration
    pub fn new(config: ReceiverConfig) -> Self {
        Receiver {
            config,
            // We need to extend SSP OTs for the consistency check.
            // Right now we only support one extension, so we just alloc
            // them here.
            alloc: SSP,
            transfer_id: TransferId::default(),
            queue: VecDeque::default(),
            state: state::Initialized {},
        }
    }

    /// Complete the setup phase of the protocol.
    ///
    /// # Arguments
    ///
    /// * `seeds` - The receiver's rng seeds
    pub fn setup(self, seeds: [[Block; 2]; CSP]) -> Receiver<state::Extension> {
        Receiver {
            config: self.config,
            alloc: self.alloc,
            transfer_id: self.transfer_id,
            queue: self.queue,
            state: state::Extension {
                rngs: seeds
                    .into_iter()
                    .map(|seeds| seeds.map(Prg::from_seed))
                    .collect(),
                msgs: Vec::default(),
                choices: Vec::default(),
                extended: false,
                unchecked_ts: vec![Vec::default(); CSP],
                unchecked_ts_trans: Vec::default(),
                unchecked_choices: Vec::default(),
            },
        }
    }
}

impl Receiver<state::Extension> {
    /// Returns `true` if the receiver wants to extend.
    pub fn wants_extend(&self) -> bool {
        self.alloc != 0 && !self.state.extended
    }

    /// Returns `true` if the receiver wants to run the consistency check.
    pub fn wants_check(&self) -> bool {
        self.alloc == 0 && !self.state.unchecked_ts.is_empty()
    }

    /// Perform the IKNP OT extension.
    pub fn extend(&mut self) -> Result<Extend, ReceiverError> {
        if self.state.extended {
            return Err(ReceiverError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        let count = self.config.batch_size().min(self.alloc);
        // Round up to a multiple of SSP, as per Figure 10:
        // "assume that s|l".
        let count = (count + (SSP - 1)) & !(SSP - 1);

        const NROWS: usize = CSP;
        let row_width = count / 8;

        let mut rng = rand::rng();
        // x₁,...,xₗ bits in Figure 3, step 1.
        let choices = (0..row_width)
            .flat_map(|_| rng.random::<u8>().into_iter_lsb0())
            .collect::<Vec<_>>();

        // 𝐱ⁱ in Figure 3. Note that it is the same for all i = 1,...,k.
        let choice_vector = Vec::<u8>::from_lsb0_iter(choices.iter().copied());

        // 𝐭₀ⁱ in Figure 3.
        let mut ts = vec![0u8; NROWS * row_width];
        let mut us = vec![0u8; NROWS * row_width];
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let iter = self.state.rngs
                    .par_iter_mut()
                    .zip(ts.par_chunks_exact_mut(row_width))
                    .zip(us.par_chunks_exact_mut(row_width));
            } else {
                let iter = self.state.rngs
                    .iter_mut()
                    .zip(ts.chunks_exact_mut(row_width))
                    .zip(us.chunks_exact_mut(row_width));
            }
        }

        iter.for_each(|((rngs, t_0), u)| {
            // Figure 3, step 2.
            rngs[0].fill_bytes(t_0);
            // reuse u to avoid memory allocation for 𝐭₁ⁱ
            rngs[1].fill_bytes(u);

            // Figure 3, step 3.
            // Computing `u = t_0 + t_1 + x`.
            u.iter_mut()
                .zip(t_0)
                .zip(&choice_vector)
                .for_each(|((u, t_0), x)| {
                    *u ^= *t_0 ^ x;
                });
        });

        // Extend existing rows.
        for (existing_row, new_row) in self
            .state
            .unchecked_ts
            .iter_mut()
            .zip(ts.chunks_exact(ts.len() / NROWS))
        {
            let new_blocks: &[Block] =
                bytemuck::try_cast_slice(new_row).expect("row length is a multiple of Block size");
            existing_row.extend_from_slice(new_blocks);
        }

        matrix_transpose::transpose_bits(&mut ts, NROWS).expect("matrix is rectangular");

        let t_blocks: &[Block] =
            bytemuck::try_cast_slice(&ts).expect("ts length is a multiple of Block size");

        self.state.unchecked_ts_trans.extend(t_blocks.iter());

        self.state.unchecked_choices.extend(choices);

        self.alloc = self.alloc.saturating_sub(count);

        Ok(Extend { count, us })
    }

    /// Performs the consistency check for all outstanding OTS.
    ///
    /// See section 4 of the paper for more details.
    ///
    /// # Arguments
    ///
    /// * `chi_seed` - The seed used to generate the consistency check weights.
    pub fn check(&mut self, chi_seed: Block) -> Result<Check, ReceiverError> {
        if !self.wants_check() {
            return Err(ReceiverError::InvalidState(
                "receiver not ready to check".to_string(),
            ));
        }

        let mut rng = Prg::from_seed(chi_seed);

        let unchecked_ts = std::mem::take(&mut self.state.unchecked_ts);
        let mut unchecked_choices = std::mem::take(&mut self.state.unchecked_choices);

        // Figure 10, "Consistency check".
        let m = unchecked_ts[0].len() - 1;

        // Figure 10, "Consistency check", point 1.
        // Sample random weights.
        let chis: Vec<Block> = (0..m).map(|_| rng.random()).collect::<Vec<_>>();

        // Figure 10, "Consistency check", point 2.
        // Compute the random linear combinations.
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let iter = unchecked_ts.into_par_iter();
            } else {
                let iter = unchecked_ts.into_iter();

            }
        }

        // tᶦ for all i = 1, ..., k.
        let check_t = iter
            .map(|mut row| {
                let last = row.pop().expect("row is not empty");
                Block::inn_prdt_red(&row, &chis) ^ last
            })
            .collect::<Vec<_>>();

        // Compute x.
        let mut bit_iter = unchecked_choices.clone().into_iter_lsb0();
        let mut xs = (0..m + 1)
            .map(|_| Block::from_lsb0_iter((&mut bit_iter).take(Block::BITS)))
            .collect::<Vec<_>>();
        let last = xs.pop().expect("xs is not empty");

        let check_x = Block::inn_prdt_red(&xs, &chis) ^ last;

        // Figure 10, "Transpose and randomize".
        // The matrix was already transposed earlier.
        // We do not randomize to remove the leakage because this is an
        // implementation of COT **with leakage**.
        let mut unchecked_ts = std::mem::take(&mut self.state.unchecked_ts_trans);

        // Strip off the rows sacrificed for the consistency check.
        let nrows = unchecked_ts.len() - SSP;
        unchecked_ts.truncate(nrows);
        unchecked_choices.truncate(nrows);

        // Add to existing msgs.
        self.state.msgs.extend_from_slice(&unchecked_ts);
        self.state.choices.extend_from_slice(&unchecked_choices);
        self.state.extended = true;

        // Resolve any queued transfers.
        if !self.queue.is_empty() {
            let mut i = 0;
            for Queued { count, sender } in mem::take(&mut self.queue) {
                let choices = self.state.choices[i..i + count].to_vec();
                let msgs = self.state.msgs[i..i + count].to_vec();
                i += count;
                sender.send(RCOTReceiverOutput {
                    id: self.transfer_id.next(),
                    choices,
                    msgs,
                });
            }

            self.state.choices.drain(..i);
            self.state.msgs.drain(..i);
        }

        Ok(Check {
            x: check_x,
            t: check_t,
        })
    }
}

impl RCOTReceiver<bool, Block> for Receiver<state::Initialized> {
    type Error = ReceiverError;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.alloc += count;

        Ok(())
    }

    fn available(&self) -> usize {
        0
    }

    fn try_recv_rcot(
        &mut self,
        _count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        Err(ReceiverError::InvalidState(
            "receiver has not been set up yet".to_string(),
        ))
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        self.queue.push_back(Queued { count, sender });

        Ok(recv)
    }
}

impl RCOTReceiver<bool, Block> for Receiver<state::Extension> {
    type Error = ReceiverError;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if self.state.extended {
            return Err(ReceiverError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        self.alloc += count;

        Ok(())
    }

    fn available(&self) -> usize {
        self.state.msgs.len()
    }

    fn try_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        if self.available() < count {
            return Err(ReceiverError::InsufficientSetup {
                expected: count,
                actual: self.available(),
            });
        }

        let choices = self.state.choices.drain(..count).collect();
        let keys = self.state.msgs.drain(..count).collect();

        Ok(RCOTReceiverOutput {
            id: self.transfer_id.next(),
            choices,
            msgs: keys,
        })
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.available() >= count {
            let output = self.try_recv_rcot(count)?;
            let (sender, recv) = new_output();
            sender.send(output);

            Ok(recv)
        } else if !self.state.extended {
            let (sender, recv) = new_output();

            self.queue.push_back(Queued { count, sender });

            Ok(recv)
        } else {
            Err(ReceiverError::InsufficientSetup {
                expected: count,
                actual: self.available(),
            })
        }
    }
}

/// The receiver's state.
pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Extension {}
    }

    /// The receiver's state.
    pub trait State: sealed::Sealed {}

    /// The receiver's initial state.
    #[derive(Default)]
    pub struct Initialized {}

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The receiver's state after the setup phase.
    ///
    /// In this state the receiver performs OT extension (potentially multiple
    /// times). Also in this state the receiver sends OT requests.
    pub struct Extension {
        /// Receiver's rngs.
        pub(super) rngs: Vec<[Prg; 2]>,

        /// Whether extension has occurred yet.
        ///
        /// This is to prevent the receiver from extending twice.
        pub(super) extended: bool,

        /// Receiver's unchecked ts before transposing.
        ///
        /// This is a row-major matrix which has [CSP] rows.
        pub(super) unchecked_ts: Vec<Vec<Block>>,

        /// Receiver's unchecked ts after transposing.
        pub(super) unchecked_ts_trans: Vec<Block>,

        /// Receiver's unchecked choices.
        pub(super) unchecked_choices: Vec<bool>,

        /// Receiver's chosen messages.
        pub(super) msgs: Vec<Block>,
        /// Receiver's random choices.
        pub(super) choices: Vec<bool>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
