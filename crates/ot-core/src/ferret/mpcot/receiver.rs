use mpz_core::Block;

type Error = MPCOTReceiverError;
type Result<T, E = Error> = core::result::Result<T, E>;

/// MPCOT receiver.
#[derive(Debug, Default)]
pub(crate) struct MPCOTReceiver<T: state::State = Initialized> {
    state: T,
}

impl MPCOTReceiver {
    /// Creates a new Receiver.
    pub(crate) fn new() -> Self {
        MPCOTReceiver {
            state: Initialized,
        }
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
        let count = idxs.len();
        if count > len {
            return Err(ErrorRepr::Params {
                count,
                len,
                reason: "indices cannot exceed vector length".to_string(),
            }
            .into());
        }

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

        Ok((
            MPCOTReceiver {
                state: Extension { len },
            },
            spcot_log2_lengths,
            idxs,
        ))
    }
}
impl MPCOTReceiver<state::Extension> {
    /// Performs MPCOT extension.
    ///
    /// See Step 5 in Figure 7.
    ///
    /// # Arguments
    ///
    /// * `ws` - The output of SPCOT.
    pub(crate) fn extend(self, ws: &[Block]) -> Result<Vec<Block>> {
        let Extension { len } = self.state;

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
}

pub(crate) mod state {
    mod sealed {
        pub(crate) trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Extension {}
    }

    pub(crate) trait State: sealed::Sealed {}

    #[derive(Debug, Default)]
    pub(crate) struct Initialized;

    impl State for Initialized {}

    #[derive(Debug)]
    pub(crate) struct Extension {
        pub(super) len: usize,
    }

    impl State for Extension {}
}

use state::{Extension, Initialized};

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};

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
            MPCOTReceiver::new()
                .start_extend(&idxs, interval_len * idx_count)
                .unwrap_err(),
            MPCOTReceiverError(ErrorRepr::NotRegular)
        ));
    }
}
