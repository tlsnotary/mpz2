use mpz_core::Block;

type Error = MPCOTSenderError;
type Result<T, E = Error> = core::result::Result<T, E>;

/// MPCOT sender.
#[derive(Debug, Default)]
pub(crate) struct MPCOTSender<T: state::State = Initialized> {
    state: T,
}

impl MPCOTSender {
    /// Creates a new Sender.
    pub(crate) fn new() -> Self {
        MPCOTSender { state: Initialized }
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

        Ok((
            MPCOTSender {
                state: Extension { len },
            },
            spcot_log2_lengths,
        ))
    }
}

impl MPCOTSender<Extension> {
    /// Performs MPCOT extension.
    ///
    /// See Step 5 in Figure 7.
    ///
    /// # Arguments
    ///
    /// * `vs` - The output of SPCOT.
    pub(crate) fn extend(self, vs: &[Block]) -> Result<Vec<Block>> {
        let Extension { len } = self.state;

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
