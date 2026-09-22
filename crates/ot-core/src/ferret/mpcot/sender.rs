use std::array::from_fn;

use mpz_core::{Block, aes::AesEncryptor, lpn::LpnType, prg::Prg, utils::slices_from_lengths};
use rand_core::SeedableRng;

use crate::ferret::cuckoo::Buckets;

type Error = MPCOTSenderError;
type Result<T, E = Error> = core::result::Result<T, E>;

/// MPCOT sender.
#[derive(Debug, Default)]
pub(crate) struct MPCOTSender<T: state::State = Initialized> {
    state: T,
}

impl MPCOTSender {
    /// Creates a new Sender.
    ///
    /// # Arguments.
    ///
    /// * `seed` - Seed for Cuckoo hash sent by the receiver.
    /// * `lpn_type` - The LPN type.
    pub(crate) fn new(seed: Block, lpn_type: LpnType) -> Self {
        let state = match lpn_type {
            LpnType::Uniform => {
                let mut prg = Prg::from_seed(seed);
                Initialized::Uniform {
                    hashes: Box::new(from_fn(|_| AesEncryptor::new(prg.random_block()))),
                }
            }
            LpnType::Regular => Initialized::Regular,
        };

        MPCOTSender { state }
    }
}

impl MPCOTSender<Initialized> {
    /// Starts the MPCOT extension.
    ///
    /// Returns the SPCOT log2 lengths.
    ///
    /// See Step 1 to Step 4 in Figure 7.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of queried indices.
    /// * `len` - Length of the vector.
    pub(crate) fn start_extend(
        self,
        count: usize,
        len: usize,
    ) -> Result<(MPCOTSender<Extension>, Vec<usize>)> {
        if count > len {
            return Err(ErrorRepr::Params {
                count,
                len,
                reason: "indices cannot exceed vector length".to_string(),
            }
            .into());
        }

        let (state, bs) = match self.state {
            Initialized::Uniform { hashes } => {
                let buckets = Buckets::new(&hashes, count, len);

                // First pad (length + 1) to a pow of 2, then computes
                // `log(length + 1)` of each bucket.
                let mut bs = vec![];
                let mut spcot_lengths = vec![];
                for len in buckets.iter_buckets() {
                    let power_of_two = (len + 1)
                        .checked_next_power_of_two()
                        .expect("bucket length should be less than usize::MAX / 2 - 1");

                    bs.push(power_of_two.ilog2() as usize);
                    spcot_lengths.push(power_of_two);
                }

                (
                    Extension::Uniform {
                        len,
                        buckets,
                        spcot_lengths,
                    },
                    bs,
                )
            }
            Initialized::Regular => {
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

                let log2_len = k.ilog2() as usize;
                let spcot_log2_lengths = (0..count).map(|_| log2_len).collect();

                (Extension::Regular { len }, spcot_log2_lengths)
            }
        };

        Ok((MPCOTSender { state }, bs))
    }
}

impl MPCOTSender<Extension> {
    /// Performs MPCOT extension.
    ///
    /// See Step 5 in Figure 7.
    ///
    /// # Arguments
    ///
    /// * `spcot` - The output of SPCOT.
    pub(crate) fn extend(self, vs: &[Block]) -> Result<Vec<Block>> {
        match self.state {
            Extension::Uniform {
                len,
                buckets,
                spcot_lengths,
            } => {
                let spcot_len = spcot_lengths.iter().sum::<usize>();
                if vs.len() != spcot_len {
                    return Err(ErrorRepr::SPCOTLength {
                        expected: spcot_len,
                        actual: vs.len(),
                    }
                    .into());
                }

                let vs = slices_from_lengths(vs, &spcot_lengths);
                let mut res = vec![Block::ZERO; len];
                for (x, &bucket_pos) in res.iter_mut().zip(buckets.iter_items()) {
                    for (bucket_idx, pos) in bucket_pos {
                        *x ^= vs[bucket_idx][pos];
                    }
                }

                Ok(res)
            }
            Extension::Regular { len } => {
                if vs.len() != len {
                    return Err(ErrorRepr::SPCOTLength {
                        expected: len,
                        actual: vs.len(),
                    }
                    .into());
                }

                Ok(vs.to_vec())
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct MPCOTSenderError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("MPCOT sender error: {0}")]
enum ErrorRepr {
    #[error("invalid parameters, count: {count}, len: {len}: {reason}")]
    Params {
        count: usize,
        len: usize,
        reason: String,
    },
    #[error("invalid length of SPCOT vector, expected: {expected}, actual: {actual}")]
    SPCOTLength { expected: usize, actual: usize },
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
