use blake3::{Hash, Hasher, hash};
use cfg_if::cfg_if;
use itybity::ToBits;
#[cfg(feature = "rayon")]
use rayon::prelude::*;

use mpz_core::{
    Block,
    bitvec::BitVec,
    cggm,
    utils::{slices_from_lengths, slices_from_lengths_mut},
};
use mpz_fields::{Field, gf2_128::Gf2_128};
use zerocopy::IntoBytes;

use crate::{
    Derandomize,
    ferret::{
        config::CSP,
        spcot::{MONOMIAL, fold_chis},
    },
};

type Error = SPCOTReceiverError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
struct Check {
    w: Gf2_128,
}

#[derive(Debug)]
pub(crate) struct SPCOTReceiver {
    /// log2 length of the SPCOT vectors pending the consistency check.
    lengths: Vec<usize>,
    /// Chosen indices of the SPCOT vectors pending the consistency check.
    indices: Vec<usize>,
    check: Option<Check>,
    transcript: Hasher,
}

impl SPCOTReceiver {
    /// Creates a new SPCOT receiver.
    pub(crate) fn new() -> Self {
        Self {
            lengths: Vec::new(),
            indices: Vec::new(),
            check: None,
            transcript: Hasher::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn wants_check(&self) -> bool {
        !self.lengths.is_empty()
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
        let len_sum: usize = log2_lengths.iter().sum();
        if idxs.len() != log2_lengths.len() {
            return Err(ErrorRepr::IndexCount {
                expected: log2_lengths.len(),
                actual: idxs.len(),
            }
            .into());
        } else if masks.len() != len_sum {
            return Err(ErrorRepr::MaskCount {
                expected: len_sum,
                actual: masks.len(),
            }
            .into());
        }

        // The path bit of level i is bit i - 1 of the index, and the COT
        // choice bit of level i must select the *opposite* side of the path.
        let flip = BitVec::from_iter(
            idxs.iter()
                .zip(log2_lengths)
                .flat_map(|(idx, &length)| idx.iter_lsb0().take(length))
                .zip(masks)
                .map(|(b, m)| !b ^ m),
        );

        let flip_len = flip.len();
        self.transcript
            .update(&flip.as_raw_slice().as_bytes()[..flip_len.div_ceil(8)]);

        Ok(Derandomize { flip })
    }

    /// Computes multiple SPCOTs, writing the SPCOT vectors to `ws`.
    ///
    /// `ws` must be presented to the consistency check unmodified.
    ///
    /// # Arguments
    ///
    /// * `log2_lengths` - log2 length of the SPCOT vectors.
    /// * `idxs` - Chosen SPCOT indices.
    /// * `macs` - COT MACs used to decrypt the cGGM tree corrections.
    /// * `cs` - cGGM tree corrections from the sender.
    /// * `ws` - Output buffer for the SPCOT vectors. The vectors are stored as
    ///   field elements; the cGGM expansion reinterprets them as raw blocks
    ///   (`Gf2_128` is little-endian, matching `Block`'s byte order on all
    ///   supported, little-endian, targets).
    pub(crate) fn extend(
        &mut self,
        log2_lengths: &[usize],
        idxs: &[usize],
        macs: &[Gf2_128],
        cs: &[Block],
        ws: &mut [Gf2_128],
    ) -> Result<()> {
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
        } else if cs.len() != len_sum {
            return Err(ErrorRepr::CorrectionCount {
                expected: len_sum,
                actual: cs.len(),
            }
            .into());
        }

        let len: usize = log2_lengths.iter().map(|length| 1 << length).sum();
        if ws.len() != len {
            return Err(ErrorRepr::OutputLength {
                expected: len,
                actual: ws.len(),
            }
            .into());
        }

        // Decrypt the off-path sibling sums: M[r_i] ⊕ c_i = !α_i * Δ ⊕ K_i^0
        // (Fig. 4 Step 4 of the Half-Tree paper).
        let sums: Vec<[u8; 16]> = macs
            .iter()
            .zip(cs)
            .map(|(&mac, &c)| (mac + Gf2_128::from(c)).to_inner().to_le_bytes())
            .collect();

        let spcot_lengths: Vec<_> = log2_lengths.iter().map(|length| 1 << length).collect();
        let sums = slices_from_lengths(&sums, log2_lengths);
        let ws = slices_from_lengths_mut(ws, &spcot_lengths);

        let iter = {
            cfg_if! {
                if #[cfg(feature = "rayon")] {
                    ws.into_par_iter()
                } else {
                    ws.into_iter()
                }
            }
        };

        iter.zip(sums).zip(idxs).for_each(|((w, sums), &idx)| {
            let w: &mut [[u8; 16]] = zerocopy::transmute_mut!(w);
            cggm::expand_punctured(idx, sums, w);

            // The leaves of the sender's tree XOR to delta, so folding the
            // punctured leaves recovers w[idx] = v[idx] ⊕ delta.
            w[idx] = w
                .iter()
                .fold(0u128, |acc, x| acc ^ u128::from_ne_bytes(*x))
                .to_ne_bytes();
        });

        self.transcript.update(cs.as_bytes());
        self.lengths.extend_from_slice(log2_lengths);
        self.indices.extend_from_slice(idxs);

        Ok(())
    }

    /// Starts a batched consistency check.
    ///
    /// # Arguments
    ///
    /// * `macs` - COT MACs.
    /// * `masks` - Random COT choice masks.
    /// * `ws` - The accumulated SPCOT vectors.
    pub(crate) fn start_check(
        &mut self,
        macs: &[Gf2_128],
        masks: &[bool],
        ws: &[Gf2_128],
    ) -> Result<Derandomize> {
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

        let len: usize = self.lengths.iter().map(|length| 1 << length).sum();
        if ws.len() != len {
            return Err(ErrorRepr::OutputLength {
                expected: len,
                actual: ws.len(),
            }
            .into());
        }

        // The global positions of the chosen indices, in ascending order.
        let mut alphas = Vec::with_capacity(self.indices.len());
        let mut i = 0;
        for (length, idx) in self.lengths.iter().zip(&self.indices) {
            alphas.push(i + idx);
            i += 1 << length;
        }

        // Computes Σₐ χₐ ⋅ wₐ and the sum of the χ at the chosen indices.
        let seed = *self.transcript.finalize().as_bytes();
        let (fold, sum_chi_alpha) = fold_chis(Block::try_from(&seed[0..16]).unwrap(), ws, &alphas);

        let x_prime = BitVec::from_iter(
            sum_chi_alpha
                .to_inner()
                .iter_lsb0()
                .zip(masks)
                .map(|(x, &x_star)| x != x_star),
        );

        // Computes W = Z + Σₐ χₐ ⋅ wₐ, where Z = Σᵢ z*ᵢ ⋅ Xⁱ.
        let w = Gf2_128::inner_product(macs, MONOMIAL) + fold;

        self.check = Some(Check { w });

        Ok(Derandomize { flip: x_prime })
    }

    /// Finishes the consistency check.
    pub(crate) fn check(&mut self, hashed_v: Hash) -> Result<()> {
        let Some(Check { w }) = self.check.take() else {
            return Err(ErrorRepr::State("check not started".to_string()).into());
        };

        // Computes H'(W)
        let hashed_w = hash(&Block::from(w).to_bytes());

        if hashed_v != hashed_w {
            return Err(ErrorRepr::Check.into());
        }

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
    #[error("incorrect correction count, expected: {expected}, actual: {actual}")]
    CorrectionCount { expected: usize, actual: usize },
    #[error("incorrect output buffer length, expected: {expected}, actual: {actual}")]
    OutputLength { expected: usize, actual: usize },
    #[error("invalid consistency check")]
    Check,
}
