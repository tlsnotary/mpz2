use blake3::{Hash, Hasher, hash};
use cfg_if::cfg_if;
use itybity::ToBits;
use rand::SeedableRng;
#[cfg(feature = "rayon")]
use rayon::prelude::*;

use mpz_core::{
    Block,
    aes::FIXED_KEY_AES,
    bitvec::BitVec,
    ggm::GgmTree,
    prg::Prg,
    utils::{slices_from_lengths, slices_from_lengths_mut},
};
use zerocopy::IntoBytes;

use crate::{Derandomize, ferret::config::CSP};

type Error = SPCOTReceiverError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
struct Check {
    z: Block,
    chis: Vec<Block>,
}

#[derive(Debug)]
pub(crate) struct SPCOTReceiver {
    ws: Vec<Block>,
    /// log2 length of the SPCOT vectors.
    lengths: Vec<usize>,
    indices: Vec<usize>,
    check: Option<Check>,
    counter: u128,
    transcript: Hasher,
}

impl SPCOTReceiver {
    /// Creates a new SPCOT receiver.
    pub(crate) fn new() -> Self {
        Self {
            ws: Vec::new(),
            lengths: Vec::new(),
            indices: Vec::new(),
            check: None,
            counter: 0,
            transcript: Hasher::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn wants_check(&self) -> bool {
        !self.ws.is_empty()
    }

    /// Derandomizes OT messages for SPCOTs.
    ///
    /// # Arguments
    ///
    /// * `log2_lengths` - log2 length of the SPCOT vectors.
    /// * `idxs` - Chosen SPCOT indices.
    /// * `masks` - Random COT choice masks.
    pub(crate) fn derandomize(
        &mut self,
        log2_lengths: &[usize],
        idxs: &[usize],
        masks: &[bool],
    ) -> Result<Derandomize> {
        let sum: usize = log2_lengths.iter().sum();
        if idxs.len() != log2_lengths.len() {
            return Err(ErrorRepr::IndexCount {
                expected: log2_lengths.len(),
                actual: idxs.len(),
            }
            .into());
        } else if masks.len() != sum {
            return Err(ErrorRepr::MaskCount {
                expected: sum,
                actual: masks.len(),
            }
            .into());
        }

        let flip = BitVec::from_iter(
            idxs.iter()
                .zip(log2_lengths)
                .flat_map(|(idx, length)| idx.iter_msb0().skip(usize::BITS as usize - length))
                .zip(masks)
                .map(|(b, m)| !b ^ m),
        );

        let flip_len = flip.len();
        self.transcript
            .update(&flip.as_raw_slice().as_bytes()[..flip_len.div_ceil(8)]);

        Ok(Derandomize { flip })
    }

    /// Computes multiple SPCOTs.
    ///
    /// Returns the SPCOT vectors.
    ///
    /// # Arguments
    ///
    /// * `log2_lengths` - log2 length of the SPCOT vectors.
    /// * `idxs` - Chosen SPCOT indices.
    /// * `macs` - COT MACs used to decrypt OT messages.
    /// * `ms` - OT messages from the sender.
    /// * `sums` - SPCOT sums from the sender.
    pub(crate) fn extend(
        &mut self,
        log2_lengths: &[usize],
        idxs: &[usize],
        macs: &[Block],
        ms: &[[Block; 2]],
        sums: &[Block],
    ) -> Result<&[Block]> {
        let len_sum: usize = log2_lengths.iter().sum();
        if idxs.len() != log2_lengths.len() {
            return Err(ErrorRepr::IndexCount {
                expected: log2_lengths.len(),
                actual: idxs.len(),
            }
            .into());
        } else if macs.len() != len_sum {
            return Err(ErrorRepr::MacCount {
                expected: len_sum,
                actual: macs.len(),
            }
            .into());
        } else if ms.len() != len_sum {
            return Err(ErrorRepr::MsgCount {
                expected: len_sum,
                actual: ms.len(),
            }
            .into());
        } else if sums.len() != log2_lengths.len() {
            return Err(ErrorRepr::SumCount {
                expected: log2_lengths.len(),
                actual: sums.len(),
            }
            .into());
        }

        let cipher = &(*FIXED_KEY_AES);
        let ggm_sums: Vec<Block> = ms
            .iter()
            .zip(macs)
            .zip(
                idxs.iter()
                    .zip(log2_lengths)
                    .flat_map(|(idx, length)| idx.iter_msb0().skip(usize::BITS as usize - length)),
            )
            .enumerate()
            .map(|(i, (([m0, m1], &t), b))| {
                let tweak = Block::from((self.counter + i as u128).to_be_bytes());
                if !b {
                    cipher.tccr(tweak, t) ^ m1
                } else {
                    cipher.tccr(tweak, t) ^ m0
                }
            })
            .collect();

        // Allocate space for the outputs.
        let len: usize = log2_lengths.iter().map(|length| 1 << length).sum();
        let start = self.ws.len();
        self.ws.resize_with(start + len, || Block::ZERO);

        let spcot_lengths: Vec<_> = log2_lengths.iter().map(|length| 1 << length).collect();
        let ggm_sums = slices_from_lengths(&ggm_sums, log2_lengths);
        let ws = slices_from_lengths_mut(&mut self.ws[start..], &spcot_lengths);

        let iter = {
            cfg_if! {
                if #[cfg(feature = "rayon")] {
                    ws.into_par_iter()
                } else {
                    ws.into_iter()
                }
            }
        };

        iter.zip(ggm_sums)
            .zip(sums)
            .zip(log2_lengths)
            .zip(idxs)
            .for_each(|((((w, sums), sum), &length), &idx)| {
                GgmTree::new_partial(length, sums, idx, w);

                w[idx] = w.iter().fold(*sum, |acc, &x| acc ^ x);
            });

        self.transcript.update(ms.as_bytes());
        self.transcript.update(sums.as_bytes());
        self.lengths.extend_from_slice(log2_lengths);
        self.indices.extend_from_slice(idxs);
        self.counter += len_sum as u128;

        Ok(&self.ws[start..])
    }

    // Starts a batched consistency check.
    pub(crate) fn start_check(&mut self, macs: &[Block], masks: &[bool]) -> Result<Derandomize> {
        if self.check.is_some() {
            return Err(ErrorRepr::State("check already started".to_string()).into());
        } else if macs.len() != CSP {
            return Err(ErrorRepr::MacCount {
                expected: CSP,
                actual: macs.len(),
            }
            .into());
        } else if masks.len() != CSP {
            return Err(ErrorRepr::MaskCount {
                expected: CSP,
                actual: masks.len(),
            }
            .into());
        }

        let seed = *self.transcript.finalize().as_bytes();
        let mut prg = Prg::from_seed(Block::try_from(&seed[0..16]).unwrap());

        // The sum of all the chi[alpha].
        let mut sum_chi_alpha = Block::ZERO;

        let mut chis = vec![Block::ZERO; self.ws.len()];
        prg.random_blocks(&mut chis);

        let mut i = 0;
        for (length, idx) in self.lengths.iter().zip(&self.indices) {
            sum_chi_alpha ^= chis[i + idx];
            i += 1 << length;
        }

        let x_prime = BitVec::from_iter(
            sum_chi_alpha
                .iter_lsb0()
                .zip(masks)
                .map(|(x, &x_star)| x != x_star),
        );

        let z = Block::inn_prdt_red(macs, &Block::MONOMIAL);

        self.check = Some(Check { z, chis });

        Ok(Derandomize { flip: x_prime })
    }

    pub(crate) fn check(&mut self, hashed_v: Hash) -> Result<()> {
        let Some(Check { z, chis }) = self.check.take() else {
            return Err(ErrorRepr::State("check not started".to_string()).into());
        };

        // Computes W.
        let w = z ^ Block::inn_prdt_red(&chis, &self.ws);

        // Computes H'(W)
        let hashed_w = hash(&w.to_bytes());

        if hashed_v != hashed_w {
            return Err(ErrorRepr::Check.into());
        }

        self.ws.clear();
        self.lengths.clear();
        self.indices.clear();
        self.transcript.reset();

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct SPCOTReceiverError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("SPCOT receiver error: {0}")]
enum ErrorRepr {
    #[error("invalid state: {0}")]
    State(String),
    #[error("incorrect index count, expected: {expected}, actual: {actual}")]
    IndexCount { expected: usize, actual: usize },
    #[error("incorrect COT MAC count, expected: {expected}, actual: {actual}")]
    MacCount { expected: usize, actual: usize },
    #[error("incorrect COT mask count, expected: {expected}, actual: {actual}")]
    MaskCount { expected: usize, actual: usize },
    #[error("incorrect OT message count, expected: {expected}, actual: {actual}")]
    MsgCount { expected: usize, actual: usize },
    #[error("incorrect SPCOT sum count, expected: {expected}, actual: {actual}")]
    SumCount { expected: usize, actual: usize },
    #[error("invalid consistency check")]
    Check,
}
