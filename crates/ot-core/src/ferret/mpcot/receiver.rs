use std::array::from_fn;

use mpz_core::{Block, aes::AesEncryptor, lpn::LpnType, prg::Prg, utils::slices_from_lengths};
use rand_core::SeedableRng;

use crate::ferret::cuckoo::{Buckets, CuckooHash, CuckooHashError};

type Error = MPCOTReceiverError;
type Result<T, E = Error> = core::result::Result<T, E>;

/// MPCOT receiver.
#[derive(Debug, Default)]
pub(crate) struct MPCOTReceiver<T: state::State = Initialized> {
    state: T,
}

impl MPCOTReceiver {
    /// Creates a new Receiver.
    ///
    /// # Arguments
    ///
    /// * `seed` - Seed for Cuckoo hashing.
    /// * `lpn_type` - The LPN type.
    pub(crate) fn new(seed: Block, lpn_type: LpnType) -> Self {
        let mut prg = Prg::from_seed(seed);
        let hashes = from_fn(|_| AesEncryptor::new(prg.random_block()));

        let state = match lpn_type {
            LpnType::Uniform => Initialized::Uniform {
                hashes: Box::new(hashes),
            },
            LpnType::Regular => Initialized::Regular,
        };

        MPCOTReceiver { state }
    }
}

impl MPCOTReceiver<state::Initialized> {
    /// Starts the MPCOT extension.
    ///
    /// Returns the SPCOT log2 lengths and indices, respectively.
    ///
    /// See Step 1 to Step 4 in Figure 7.
    ///
    /// # Arguments
    ///
    /// * `idxs` - The queried indices.
    /// * `len` - Length of the vector.
    pub(crate) fn start_extend(
        self,
        idxs: &[usize],
        len: usize,
    ) -> Result<(MPCOTReceiver<state::Extension>, Vec<usize>, Vec<usize>)> {
        if idxs.len() > len {
            return Err(ErrorRepr::Params {
                count: idxs.len(),
                len,
                reason: "indices cannot exceed vector length".to_string(),
            }
            .into());
        }

        let (state, lengths, idxs) = match self.state {
            Initialized::Uniform { hashes } => {
                let cuckoo = CuckooHash::new(&hashes, idxs).map_err(ErrorRepr::from)?;
                let buckets = Buckets::new(&hashes, idxs.len(), len);

                // Generates queries for SPCOT.
                // See Step 4 in Figure 7.
                let mut idxs = vec![];
                let mut spcot_log2_lengths = vec![];
                let mut spcot_lengths = vec![];
                for (item, bucket_length) in cuckoo.iter().zip(buckets.iter_buckets()) {
                    // pad to power of 2.
                    let power_of_two = (bucket_length + 1)
                        .checked_next_power_of_two()
                        .expect("bucket length should be less than usize::MAX / 2 - 1");

                    if let Some(x) = item {
                        let (_, pos) = buckets.get(x.value as usize)[x.hash_idx as usize];

                        idxs.push(pos);
                    } else {
                        // Acc.to p.10 "if T[j] is empty ... then the receiver's
                        // input p_j can point to this
                        // extra cell".
                        idxs.push(bucket_length);
                    }

                    spcot_log2_lengths.push(power_of_two.ilog2() as usize);
                    spcot_lengths.push(power_of_two);
                }

                (
                    Extension::Uniform {
                        len,
                        buckets,
                        spcot_lengths,
                    },
                    spcot_log2_lengths,
                    idxs,
                )
            }
            Initialized::Regular => {
                let count = idxs.len();
                // The length of each interval.
                let k = len / count;
                if !len.is_multiple_of(count) {
                    return Err(ErrorRepr::Params {
                        count,
                        len,
                        reason: "len should be a multiple of count".to_string(),
                    }
                    .into());
                } else if !k.is_power_of_two() {
                    return Err(ErrorRepr::Params {
                        count,
                        len,
                        reason: "regular interval length must be a power of two".to_string(),
                    }
                    .into());
                }

                if !idxs
                    .iter()
                    .enumerate()
                    .all(|(i, &idx)| i * k <= idx && idx < (i + 1) * k)
                {
                    return Err(ErrorRepr::NotRegular.into());
                }

                let log2_len = k.ilog2() as usize;
                let spcot_log2_lengths = (0..count).map(|_| log2_len).collect();
                let idxs = idxs.iter().map(|&idx| idx % k).collect();

                (Extension::Regular { len }, spcot_log2_lengths, idxs)
            }
        };

        Ok((MPCOTReceiver { state }, lengths, idxs))
    }
}
impl MPCOTReceiver<state::Extension> {
    /// Performs MPCOT extension.
    ///
    /// See Step 5 in Figure 7.
    ///
    /// # Arguments
    ///
    /// * `spcot` - The output of SPCOT.
    pub(crate) fn extend(self, ws: &[Block]) -> Result<Vec<Block>> {
        match self.state {
            Extension::Uniform {
                len,
                buckets,
                spcot_lengths,
            } => {
                let spcot_len = spcot_lengths.iter().sum::<usize>();
                if ws.len() != spcot_len {
                    return Err(ErrorRepr::SPCOTLength {
                        expected: spcot_len,
                        actual: ws.len(),
                    }
                    .into());
                }

                let ws = slices_from_lengths(ws, &spcot_lengths);
                let mut res = vec![Block::ZERO; len];
                for (x, &bucket_pos) in res.iter_mut().zip(buckets.iter_items()) {
                    for (bucket_idx, pos) in bucket_pos {
                        *x ^= ws[bucket_idx][pos];
                    }
                }

                Ok(res)
            }
            Extension::Regular { len } => {
                if ws.len() != len {
                    return Err(ErrorRepr::SPCOTLength {
                        expected: len,
                        actual: ws.len(),
                    }
                    .into());
                }

                Ok(ws.to_vec())
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct MPCOTReceiverError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("MPCOT sender error: {0}")]
enum ErrorRepr {
    #[error("invalid parameters, count: {count}, len: {len}: {reason}")]
    Params {
        count: usize,
        len: usize,
        reason: String,
    },
    #[error("input indices are not regular")]
    NotRegular,
    #[error("invalid length of SPCOT vector, expected: {expected}, actual: {actual}")]
    SPCOTLength { expected: usize, actual: usize },
    #[error("cuckoo hash error: {0}")]
    Cuckoo(#[from] CuckooHashError),
}

pub(crate) mod state {
    use crate::ferret::cuckoo::HASH_NUM;

    use super::*;

    mod sealed {
        pub(crate) trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Extension {}
    }

    pub(crate) trait State: sealed::Sealed {}

    pub(crate) enum Initialized {
        Uniform {
            hashes: Box<[AesEncryptor; HASH_NUM as usize]>,
        },
        Regular,
    }

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    pub(crate) enum Extension {
        Uniform {
            len: usize,
            buckets: Buckets,
            spcot_lengths: Vec<usize>,
        },
        Regular {
            len: usize,
        },
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}

use state::{Extension, Initialized};

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    #[test]
    fn test_indices_not_regular() {
        let mut rng = StdRng::seed_from_u64(0);

        let interval_len = 8;
        let idx_count = 4;
        let mut idxs: Vec<_> = (0..idx_count)
            .map(|i| rng.random_range(interval_len * i..interval_len * (i + 1)))
            .collect();

        //Corrupt an index.
        idxs[idx_count - 1] = idxs[idx_count - 2];

        assert!(matches!(
            MPCOTReceiver::new(rng.random(), LpnType::Regular)
                .start_extend(&idxs, interval_len * idx_count)
                .unwrap_err(),
            MPCOTReceiverError(ErrorRepr::NotRegular)
        ));
    }
}
