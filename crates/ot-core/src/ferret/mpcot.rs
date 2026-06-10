//! Multi-Point COT (MPCOT) for regular error distributions.
//!
//! See Figure 7 in the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) paper.
//!
//! With a regular error distribution every queried index falls in its own
//! interval, so the MPCOT extension reduces to one SPCOT per interval and the
//! MPCOT output *is* the concatenation of the SPCOT outputs. The functions
//! here only plan that reduction: they validate the parameters and derive the
//! SPCOT lengths and indices.

type Error = MPCOTError;
type Result<T, E = Error> = core::result::Result<T, E>;

/// Plans the SPCOT expansion for an MPCOT extension.
///
/// Returns the SPCOT log2 lengths.
///
/// See Step 1 to Step 4 in Figure 7.
///
/// # Arguments
///
/// * `count` - Number of queried indices.
/// * `len` - Length of the vector.
pub(crate) fn spcot_lengths(count: usize, len: usize) -> Result<Vec<usize>> {
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

    let log2_len = k.ilog2() as usize;

    Ok((0..count).map(|_| log2_len).collect())
}

/// Plans the SPCOT expansion for an MPCOT extension with the queried indices.
///
/// Returns the SPCOT log2 lengths and indices, respectively.
///
/// See Step 1 to Step 4 in Figure 7.
///
/// # Arguments
///
/// * `idxs` - The queried indices.
/// * `len` - Length of the vector.
pub(crate) fn spcot_queries(idxs: &[usize], len: usize) -> Result<(Vec<usize>, Vec<usize>)> {
    let lengths = spcot_lengths(idxs.len(), len)?;

    let k = len / idxs.len();
    if !idxs
        .iter()
        .enumerate()
        .all(|(i, &idx)| i * k <= idx && idx < (i + 1) * k)
    {
        return Err(ErrorRepr::NotRegular.into());
    }

    let idxs = idxs.iter().map(|&idx| idx % k).collect();

    Ok((lengths, idxs))
}

/// MPCOT error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct MPCOTError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("MPCOT error: {0}")]
enum ErrorRepr {
    #[error("invalid parameters, count: {count}, len: {len}: {reason}")]
    Params {
        count: usize,
        len: usize,
        reason: String,
    },
    #[error("input indices are not regular")]
    NotRegular,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ferret::spcot::spcot;
    use mpz_core::lpn::sample_error_indices;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    #[test]
    fn test_mpcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = rng.random();

        let n = 10;
        let indices = sample_error_indices(&mut rng, n, 5);

        let sender_lengths = spcot_lengths(indices.len(), n).unwrap();
        let (receiver_lengths, receiver_idxs) = spcot_queries(&indices, n).unwrap();

        assert_eq!(sender_lengths, receiver_lengths);

        // The concatenated SPCOT outputs are the MPCOT outputs: the punctured
        // points land at the queried global indices.
        let (vs, ws) = spcot(&mut rng, &sender_lengths, &receiver_idxs, delta);

        let mut expected = vs.clone();
        for idx in indices {
            expected[idx] ^= delta;
        }

        assert_eq!(ws, expected);
    }

    #[test]
    fn test_indices_not_regular() {
        let mut rng = StdRng::seed_from_u64(0);

        let interval_len = 8;
        let idx_count = 4;
        let mut idxs: Vec<_> = (0..idx_count)
            .map(|i| rng.random_range(interval_len * i..interval_len * (i + 1)))
            .collect();

        // Corrupt an index.
        idxs[idx_count - 1] = idxs[idx_count - 2];

        assert!(matches!(
            spcot_queries(&idxs, interval_len * idx_count).unwrap_err(),
            MPCOTError(ErrorRepr::NotRegular)
        ));
    }
}
