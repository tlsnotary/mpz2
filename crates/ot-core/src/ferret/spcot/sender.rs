use blake3::{Hash, Hasher, hash};
use cfg_if::cfg_if;
use rand::{Rng, RngExt, SeedableRng};
#[cfg(feature = "rayon")]
use rayon::prelude::*;

use mpz_core::{
    Block, aes::FIXED_KEY_AES, bitvec::BitVec, ggm::GgmTree, prg::Prg,
    utils::slices_from_lengths_mut,
};
use zerocopy::IntoBytes;

use crate::ferret::config::CSP;

type Error = SPCOTSenderError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub(crate) struct SPCOTSender {
    vs: Vec<Block>,
    delta: Block,
    counter: u128,
    transcript: Hasher,
}

impl SPCOTSender {
    /// Creates a new SPCOT sender.
    pub(crate) fn new(delta: Block) -> Self {
        Self {
            vs: Vec::new(),
            delta,
            counter: 0,
            transcript: Hasher::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn delta(&self) -> Block {
        self.delta
    }

    #[cfg(test)]
    pub(crate) fn wants_check(&self) -> bool {
        !self.vs.is_empty()
    }

    /// Computes multiple SPCOTs.
    ///
    /// Returns the SPCOT vectors, OT messages and SPCOT sums.
    ///
    /// # Arguments
    ///
    /// * `log2_lengths` - log2 length of the SPCOT vectors.
    /// * `keys` - COT keys.
    /// * `masks` - Derandomized COT choices bits from the receiver.
    #[allow(clippy::type_complexity)]
    pub(crate) fn extend<R: Rng>(
        &mut self,
        rng: &mut R,
        log2_lengths: &[usize],
        keys: &[Block],
        masks: &BitVec,
    ) -> Result<(&[Block], Vec<[Block; 2]>, Vec<Block>)> {
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

        // Compute OT keys.
        let cipher = &(*FIXED_KEY_AES);
        let mut ms: Vec<_> = keys
            .iter()
            .zip(masks.iter().by_vals())
            .enumerate()
            .map(|(i, (key, b))| {
                let mut m = if b {
                    [key ^ self.delta, *key]
                } else {
                    [*key, key ^ self.delta]
                };
                let tweak = Block::from((self.counter + i as u128).to_be_bytes());
                cipher.tccr_many(&[tweak, tweak], &mut m);
                m
            })
            .collect();

        // Allocate space for the outputs.
        let len: usize = log2_lengths.iter().map(|length| 1 << length).sum();
        let start = self.vs.len();
        self.vs.resize_with(start + len, || Block::ZERO);

        let spcot_lengths: Vec<_> = log2_lengths.iter().map(|length| 1 << length).collect();
        let seeds: Vec<Block> = (0..log2_lengths.len()).map(|_| rng.random()).collect();
        let vs = slices_from_lengths_mut(&mut self.vs[start..], &spcot_lengths);
        let ks = slices_from_lengths_mut(&mut ms, log2_lengths);

        let iter = {
            cfg_if! {
                if #[cfg(feature = "rayon")] {
                    vs.into_par_iter()
                } else {
                    vs.into_iter()
                }
            }
        };

        let sums: Vec<_> = iter
            .zip(ks)
            .zip(log2_lengths)
            .zip(seeds)
            .map(|(((v, ks), &depth), seed)| {
                // Generate the SPCOT vector from GGM leaves.
                let tree = GgmTree::new_from_seed(depth, seed, v);

                // Encrypt the OT messages.
                tree.layer_sums().zip(ks).for_each(|(sums, ks)| {
                    // `sums` is K_0 and K_1 in Fig. 6 Step 3.
                    ks[0] ^= sums[0];
                    ks[1] ^= sums[1];
                });

                // Compute the sum of the leaves.
                tree.leaves().iter().fold(self.delta, |acc, x| acc ^ x)
            })
            .collect();

        let masks_len = masks.len();
        self.transcript
            .update(&masks.as_raw_slice().as_bytes()[..masks_len.div_ceil(8)]);
        self.transcript.update(Block::array_as_flattened_bytes(&ms));
        self.transcript.update(Block::as_flattened_bytes(&sums));
        self.counter += len_sum as u128;

        Ok((&self.vs[start..], ms, sums))
    }

    /// Performs the SPCOT consistency check.
    ///
    /// # Arguments
    ///
    /// * `keys` - COT keys.
    /// * `masks` - Derandomized COT choice bits from the receiver.
    pub(crate) fn check(&mut self, keys: &[Block], masks: &BitVec) -> Result<Hash> {
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
        }

        // Step 8 in Figure 6.

        // Computes y = y_star + x' * Delta
        let y: Vec<Block> = keys
            .iter()
            .zip(masks.iter().by_vals())
            .map(|(&y, x)| if x { y ^ self.delta } else { y })
            .collect();

        // Computes Y
        let mut v = Block::inn_prdt_red(&y, &Block::MONOMIAL);

        // Computes V
        let seed = *self.transcript.finalize().as_bytes();
        let mut prg = Prg::from_seed(Block::try_from(&seed[0..16]).unwrap());

        let mut chis = vec![Block::ZERO; self.vs.len()];
        prg.random_blocks(&mut chis);

        v ^= Block::inn_prdt_red(&chis, &self.vs);

        // Computes H'(V)
        let hashed_v = hash(&v.to_bytes());

        self.vs.clear();
        self.transcript.reset();

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
}
