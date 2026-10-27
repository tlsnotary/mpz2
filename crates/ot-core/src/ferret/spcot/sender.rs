use blake3::{Hash, hash};
use cfg_if::cfg_if;
use itybity::FromBitIterator;
use rand::Rng;
#[cfg(not(feature = "emp"))]
use rand::RngExt;
#[cfg(feature = "rayon")]
use rayon::prelude::*;

use mpz_core::{Block, bitvec::BitVec, cggm, utils::slices_from_lengths_mut};
use mpz_fields::{Field, gf2_128::Gf2_128};

use crate::ferret::{
    config::CSP,
    spcot::{MONOMIAL, fold_chis},
};

type Error = SPCOTSenderError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub(crate) struct SPCOTSender {
    /// Total length of the SPCOT vectors pending the consistency check.
    pending: usize,
    delta: Block,
}

impl SPCOTSender {
    /// Creates a new SPCOT sender.
    pub(crate) fn new(delta: Block) -> Self {
        Self { pending: 0, delta }
    }

    #[cfg(test)]
    pub(crate) fn delta(&self) -> Block {
        self.delta
    }

    #[cfg(test)]
    pub(crate) fn wants_check(&self) -> bool {
        self.pending != 0
    }

    /// Computes multiple SPCOTs, writing the SPCOT vectors to `vs`.
    ///
    /// Returns the cGGM tree corrections. `vs` must be presented to the
    /// consistency check unmodified.
    ///
    /// # Arguments
    ///
    /// * `log2_lengths` - log2 length of the SPCOT vectors.
    /// * `keys` - COT keys.
    /// * `masks` - Derandomized COT choices bits from the receiver.
    /// * `vs` - Output buffer for the SPCOT vectors. The vectors are stored as
    ///   field elements; the cGGM expansion reinterprets them as raw blocks
    ///   (`Gf2_128` is little-endian, matching `Block`'s byte order on all
    ///   supported, little-endian, targets).
    pub(crate) fn extend<R: Rng>(
        &mut self,
        rng: &mut R,
        log2_lengths: &[usize],
        keys: &[Gf2_128],
        masks: &BitVec,
        vs: &mut [Gf2_128],
    ) -> Result<Vec<Block>> {
        let len_sum: usize = log2_lengths.iter().sum();
        if keys.len() != len_sum {
            return Err(ErrorRepr::KeyCount {
                expected: len_sum,
                actual: keys.len(),
            }
            .into());
        } else if masks.len() != len_sum {
            return Err(ErrorRepr::MaskCount {
                expected: len_sum,
                actual: masks.len(),
            }
            .into());
        }

        let len: usize = log2_lengths.iter().map(|length| 1 << length).sum();
        if vs.len() != len {
            return Err(ErrorRepr::OutputLength {
                expected: len,
                actual: vs.len(),
            }
            .into());
        }

        // Derandomize the COT keys. After expansion these become the per-level
        // corrections c_i = K[r_i] ⊕ b_i * Δ ⊕ K_i^0, where K_i^0 is the
        // left-node sum at level i of the cGGM tree (Fig. 4 Step 3 of the
        // Half-Tree paper, https://eprint.iacr.org/2022/1431).
        let delta = self.delta;
        let delta_f = Gf2_128::from(delta);
        let mut cs: Vec<Block> = keys
            .iter()
            .zip(masks.iter().by_vals())
            .map(|(&key, b)| Block::from(if b { key + delta_f } else { key }))
            .collect();

        let spcot_lengths: Vec<_> = log2_lengths.iter().map(|length| 1 << length).collect();
        let seeds: Vec<[u8; 16]> = (0..log2_lengths.len())
            .map(|_| {
                // Raw PRG bytes; `Rng::random` would reorder them.
                #[cfg(feature = "emp")]
                {
                    let mut seed = [0u8; 16];
                    rand::Rng::fill_bytes(rng, &mut seed);
                    seed
                }
                #[cfg(not(feature = "emp"))]
                {
                    rng.random()
                }
            })
            .collect();
        let vs = slices_from_lengths_mut(vs, &spcot_lengths);
        let cs_trees = slices_from_lengths_mut(&mut cs, log2_lengths);

        let iter = {
            cfg_if! {
                if #[cfg(feature = "rayon")] {
                    vs.into_par_iter()
                } else {
                    vs.into_iter()
                }
            }
        };

        iter.zip(cs_trees).zip(seeds).for_each(|((v, cs), seed)| {
            // Generate the SPCOT vector from the cGGM leaves. The leaves of
            // every tree XOR to delta, which carries the punctured-point
            // correlation for free.
            //
            // The sums buffer lives on the stack: a tree deeper than 64
            // levels is impossible, as its leaves could not be allocated.
            let v: &mut [[u8; 16]] = zerocopy::transmute_mut!(v);
            let mut sums = [[0u8; 16]; 64];
            let sums = &mut sums[..cs.len()];
            cggm::expand(delta.to_bytes(), seed, v, sums);

            for (c, sum) in cs.iter_mut().zip(sums) {
                *c ^= Block::from(*sum);
            }
        });

        self.pending += len;

        Ok(cs)
    }

    /// Performs the SPCOT consistency check.
    ///
    /// # Arguments
    ///
    /// * `keys` - COT keys.
    /// * `masks` - Derandomized COT choice bits from the receiver.
    /// * `vs` - The accumulated SPCOT vectors.
    pub(crate) fn check(
        &mut self,
        keys: &[Gf2_128],
        masks: &BitVec,
        vs: &[Gf2_128],
        chi_seed: Block,
    ) -> Result<Hash> {
        if keys.len() != CSP {
            return Err(ErrorRepr::KeyCount {
                expected: CSP,
                actual: keys.len(),
            }
            .into());
        } else if masks.len() != CSP {
            return Err(ErrorRepr::MaskCount {
                expected: CSP,
                actual: masks.len(),
            }
            .into());
        } else if vs.len() != self.pending {
            return Err(ErrorRepr::OutputLength {
                expected: self.pending,
                actual: vs.len(),
            }
            .into());
        }

        // Step 8 in Figure 6.

        // Computes Y = Σᵢ yᵢ ⋅ Xⁱ, where yᵢ = y*ᵢ + x'ᵢ ⋅ Δ. By linearity this
        // is Σᵢ y*ᵢ ⋅ Xⁱ + x' ⋅ Δ, where x' is the choice bits packed into a
        // field element.
        let x = Gf2_128::from_lsb0_iter(masks.iter().by_vals());
        let y = Gf2_128::inner_product(keys, MONOMIAL) + Gf2_128::from(self.delta) * x;

        // Computes V = Y + Σₐ χₐ ⋅ vₐ
        let (fold, _) = fold_chis(chi_seed, vs, &[]);
        let v = y + fold;

        // Computes H'(V)
        let hashed_v = hash(&Block::from(v).to_bytes());

        self.pending = 0;

        Ok(hashed_v)
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct SPCOTSenderError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("SPCOT sender error: {0}")]
enum ErrorRepr {
    #[error("incorrect key count, expected: {expected}, actual: {actual}")]
    KeyCount { expected: usize, actual: usize },
    #[error("incorrect mask count, expected: {expected}, actual: {actual}")]
    MaskCount { expected: usize, actual: usize },
    #[error("incorrect output buffer length, expected: {expected}, actual: {actual}")]
    OutputLength { expected: usize, actual: usize },
}
