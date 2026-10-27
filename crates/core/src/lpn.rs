//! Implement LPN with local linear code.
//! More specifically, a local linear code is a random boolean matrix with at
//! most D non-zero values in each row.

use crate::prp::Prp;
use rand::{Rng, RngExt};

/// An LPN encoder.
///
/// The `seed` defines a sparse binary matrix `A` with at most `D` non-zero
/// values in each row.
///
/// Given a vector `x` and `e`, compute `y = Ax + e`.
///
/// `A` - is a binary matrix with `k` columns and `n` rows. The concrete number
/// of `n` is determined by the input length. `A` will be generated on-the-fly.
///
/// `x` - is a `F_{2^128}` vector with length `k`.
///
/// `e` - is a `F_{2^128}` vector with length `n`.
///
/// Note that in the standard LPN problem, `x` is a binary vector, `e` is a
/// sparse binary vector. The way we defined here is a more generic way in term
/// of computing `y`.
pub struct LpnEncoder<const D: usize> {
    /// The length of the secret, i.e., x.
    k: u32,
    /// Reduction mask, equal to `k - 1` (valid since `k` is a power of two).
    mask: u32,
}

/// Number of 4-row groups whose index-generation AES blocks are issued in a
/// single batched call. Each group needs `D` AES blocks, so a batch encrypts
/// `GROUPS * D` blocks at once — large enough to keep a software AES backend
/// (e.g. on WASM, which has no AES instructions) saturated. Tuning knob.
const GROUPS: usize = 4;

/// Builds the AES plaintext block that selects the `D` column indices for the
/// 4-row group starting at row `pos`, lane `d`.
///
/// By default the two 64-bit halves are filled independently — low half `pos`,
/// high half `d` — so each 4-row group derives its indices from its own
/// position alone (trivially parallel, no shared stream state). The halves are
/// transmuted in native order, so the PRP input is little-endian only.
///
/// With the `emp` feature the fields are collapsed into the single
/// monotone counter `(pos / 4) * D + d` (high half zero) that emp-ot's `PRG`
/// consumes, turning this PRP into emp-ot's PRG stream so a test can reproduce
/// its matrix `A` byte-for-byte. Exact equivalence also requires the output
/// length to be a multiple of 4: emp-ot's sub-4 tail consumes its blocks in a
/// different quantization (it pads each single-row batch to a block and the
/// two padding words are discarded).
#[inline(always)]
fn index_block<const D: usize>(pos: u64, d: u64) -> [u32; 4] {
    #[cfg(feature = "emp")]
    {
        let counter = (pos / 4) * D as u64 + d;
        // Low half = counter, high half = 0, matching emp-tool's
        // `makeBlock(0, counter)` and this crate's own `Prg` stream.
        zerocopy::transmute!([counter, 0u64])
    }
    #[cfg(not(feature = "emp"))]
    {
        zerocopy::transmute!([pos, d])
    }
}
impl<const D: usize> LpnEncoder<D> {
    /// Create a new LPN instance.
    ///
    /// # Panics
    ///
    /// Panics if `k` is not a power of two.
    pub fn new(k: u32) -> Self {
        assert!(k.is_power_of_two(), "k must be a power of two");
        Self { k, mask: k - 1 }
    }

    /// Generates the column indices for `n_groups` groups of 4 rows, starting
    /// at row `base` (a multiple of 4).
    ///
    /// All index-generation AES blocks for the chunk are produced in a single
    /// batched call so the (software) AES backend stays saturated. Each group
    /// of 4 rows shares `D` AES blocks, since one 128-bit block expands to
    /// four `u32` column indices: row `i` of a group takes the `i`-th run
    /// of `D` indices of the flattened group.
    #[inline]
    fn compute_indices(&self, base: usize, n_groups: usize, prp: &Prp) -> [[[u32; 4]; D]; GROUPS] {
        // Counter blocks: group `c` uses `index_block::<D>(base + 4c, d)`.
        let mut idx = [[[0u32; 4]; D]; GROUPS];
        for (c, group) in idx[..n_groups].iter_mut().enumerate() {
            let pos = (base + 4 * c) as u64;
            for (d, block) in group.iter_mut().enumerate() {
                *block = index_block::<D>(pos, d as u64);
            }
        }

        let blocks: &mut [[u8; 16]] = zerocopy::transmute_mut!(idx[..n_groups].as_flattened_mut());
        prp.permute_block_inplace(blocks);

        idx
    }

    /// Computes up to `4 * GROUPS` rows of the output, starting at row `base`
    /// (a multiple of 4).
    #[inline]
    fn compute_rows(&self, y: &mut [[u8; 16]], x: &[[u8; 16]], base: usize, prp: &Prp) {
        let n_groups = y.len().div_ceil(4);
        let idx = self.compute_indices(base, n_groups, prp);

        for (c, group) in idx[..n_groups].iter().enumerate() {
            let row0 = 4 * c;
            for (i, col) in group
                .as_flattened()
                .chunks_exact(D)
                .enumerate()
                .take(y.len() - row0)
            {
                let mut acc = u128::from_ne_bytes(y[row0 + i]);
                for &raw in col {
                    acc ^= u128::from_ne_bytes(x[(raw & self.mask) as usize]);
                }
                y[row0 + i] = acc.to_ne_bytes();
            }
        }
    }

    /// Computes up to `4 * GROUPS` rows of the block output and the
    /// bit-packed output, starting at row `base` (a multiple of 8), sharing
    /// a single index generation.
    #[inline]
    fn compute_rows_with_bits(
        &self,
        y: &mut [[u8; 16]],
        y_bits: &mut [u8],
        x: &[[u8; 16]],
        x_bits: &[u8],
        base: usize,
        prp: &Prp,
    ) {
        let n_groups = y.len().div_ceil(4);
        let idx = self.compute_indices(base, n_groups, prp);

        // `column & mask <= mask < x.len()`: lets the compiler elide the
        // bounds checks in the gather loop.
        let mask = self.mask as usize;
        let x = &x[..mask + 1];
        let x_bits = &x_bits[..mask / 8 + 1];

        for (c, group) in idx[..n_groups].iter().enumerate() {
            let row0 = 4 * c;
            for (i, col) in group
                .as_flattened()
                .chunks_exact(D)
                .enumerate()
                .take(y.len() - row0)
            {
                let row = row0 + i;
                let mut acc = u128::from_ne_bytes(y[row]);
                let mut bit = 0u8;
                for &raw in col {
                    let j = raw as usize & mask;
                    acc ^= u128::from_ne_bytes(x[j]);
                    bit ^= x_bits[j / 8] >> (j % 8);
                }
                y[row] = acc.to_ne_bytes();
                y_bits[row / 8] ^= (bit & 1) << (row % 8);
            }
        }
    }

    /// Compute `Ax + e`, writing the result in-place into `y`.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed for PRP.
    /// * `y` - Error vector with length `n`, this is actually `e` in LPN.
    /// * `x` - Secret vector with length `k`.
    ///
    /// # Panics
    ///
    /// Panics if `x.len() !=k` or `y.len() != n`.
    pub fn compute(&self, seed: [u8; 16], y: &mut [[u8; 16]], x: &[[u8; 16]]) {
        assert_eq!(x.len() as u32, self.k);
        assert!(x.len() >= D);
        let prp = Prp::new(seed);

        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                use rayon::prelude::*;

                let iter = y.par_chunks_mut(4 * GROUPS).enumerate();
            } else {
                let iter = y.chunks_mut(4 * GROUPS).enumerate();
            }
        }

        iter.for_each(|(chunk, y)| {
            self.compute_rows(y, x, chunk * 4 * GROUPS, &prp);
        });
    }

    /// Computes `Ax + e` and `A·x_bits + e_bits` over GF(2) in one pass,
    /// writing the results in-place into `y` and `y_bits`.
    ///
    /// Both encodings use the same matrix `A` (identical to
    /// [`LpnEncoder::compute`] with the same seed), sharing a single index
    /// generation. `x_bits` and `y_bits` are bit-packed in LSB0 order, i.e.
    /// bit `i` is bit `i % 8` of byte `i / 8`, with bit `i` of `y_bits`
    /// corresponding to row `i` of `y`.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed for PRP.
    /// * `y` - Error vector with length `n`, this is actually `e` in LPN.
    /// * `y_bits` - Bit-packed error vector with length `n = 8 * y_bits.len()`.
    /// * `x` - Secret vector with length `k`.
    /// * `x_bits` - Bit-packed secret vector with length `k = 8 *
    ///   x_bits.len()`.
    ///
    /// # Panics
    ///
    /// Panics if `x.len() != k`, `8 * x_bits.len() != k`, or
    /// `y_bits.len() != y.len().div_ceil(8)`.
    pub fn compute_with_bits(
        &self,
        seed: [u8; 16],
        y: &mut [[u8; 16]],
        y_bits: &mut [u8],
        x: &[[u8; 16]],
        x_bits: &[u8],
    ) {
        assert_eq!(x.len() as u32, self.k);
        assert_eq!(x_bits.len() as u32 * 8, self.k);
        assert_eq!(y_bits.len(), y.len().div_ceil(8));
        assert!(x.len() >= D);
        let prp = Prp::new(seed);

        const CHUNK: usize = 4 * GROUPS;

        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                use rayon::prelude::*;

                let iter = y
                    .par_chunks_mut(CHUNK)
                    .zip(y_bits.par_chunks_mut(CHUNK / 8))
                    .enumerate();
            } else {
                let iter = y.chunks_mut(CHUNK).zip(y_bits.chunks_mut(CHUNK / 8)).enumerate();
            }
        }

        iter.for_each(|(chunk, (y, y_bits))| {
            self.compute_rows_with_bits(y, y_bits, x, x_bits, chunk * CHUNK, &prp);
        });
    }
}

/// Lpn paramters
#[derive(Copy, Clone, Debug)]
pub struct LpnParameters {
    /// Length of the output vector.
    pub n: usize,
    /// Length of the secret vector.
    pub k: usize,
    /// Hamming weight of the error vector.
    pub t: usize,
}

/// Samples indices for non-zero entries in a regular error vector.
///
/// The error vector is divided into `count` equal-length intervals, with a
/// single non-zero entry sampled uniformly within each interval.
///
/// # Panics
///
/// Panics if `len` is not a multiple of `count`.
///
/// # Arguments
///
/// * `rng` - Random number generator.
/// * `len` - Length of the error vector.
/// * `count` - Hamming weight.
pub fn sample_error_indices<R: Rng>(rng: &mut R, len: usize, count: usize) -> Vec<usize> {
    assert_eq!(len % count, 0);
    let step = len / count;
    (0..count)
        .map(|i| rng.random_range(i * step..(i + 1) * step))
        .collect()
}

impl LpnParameters {
    /// Create a new LpnParameters instance.
    pub fn new(n: usize, k: usize, t: usize) -> Self {
        assert!(t <= n);
        LpnParameters { n, k, t }
    }
}

#[cfg(test)]
mod tests {
    use crate::{lpn::LpnEncoder, prp::Prp};

    impl<const D: usize> LpnEncoder<D> {
        /// A naive, obviously-correct reference for [`LpnEncoder::compute`],
        /// used to cross-check the batched implementation.
        pub(crate) fn compute_naive(&self, seed: [u8; 16], y: &mut [[u8; 16]], x: &[[u8; 16]]) {
            assert_eq!(x.len() as u32, self.k);
            assert!(x.len() >= D);
            let prp = Prp::new(seed);

            for (r, y) in y.iter_mut().enumerate() {
                // Row `r` shares its `D` AES blocks with the other rows of its
                // 4-row group, taking the `(r % 4)`-th run of `D` indices.
                let pos = (r / 4 * 4) as u64;
                let lane = r % 4;

                let mut idx = [[0u32; 4]; D];
                for (d, block) in idx.iter_mut().enumerate() {
                    // Shares the batched path's index source (see `index_block`),
                    // so the cross-check stays valid under `emp`.
                    *block = super::index_block::<D>(pos, d as u64);
                }
                let blocks: &mut [[u8; 16]] = zerocopy::transmute_mut!(idx.as_mut_slice());
                prp.permute_block_inplace(blocks);

                let cols = idx.as_flattened();
                let mut acc = u128::from_ne_bytes(*y);
                for &raw in &cols[lane * D..(lane + 1) * D] {
                    acc ^= u128::from_ne_bytes(x[(raw & self.mask) as usize]);
                }
                *y = acc.to_ne_bytes();
            }
        }
    }

    #[test]
    fn lpn_with_bits_test() {
        use crate::{lpn::LpnEncoder, prg::Prg};

        let k = 512usize;
        let n = 1000usize;
        let lpn = LpnEncoder::<10>::new(k as u32);
        let mut prg = Prg::new();

        let mut x = vec![[0u8; 16]; k];
        let mut y = vec![[0u8; 16]; n];
        let mut x_bits = vec![0u8; k / 8];
        let mut y_bits = vec![0u8; n.div_ceil(8)];
        prg.random_bytes(x.as_flattened_mut());
        prg.random_bytes(y.as_flattened_mut());
        prg.random_bytes(&mut x_bits);
        prg.random_bytes(&mut y_bits);

        // Embed the bits into the LSBs of blocks to cross-check the
        // bit-packed output against the block encoding.
        let embed = |bits: &[u8], len: usize| -> Vec<[u8; 16]> {
            (0..len)
                .map(|i| {
                    let mut block = [0u8; 16];
                    block[0] = (bits[i / 8] >> (i % 8)) & 1;
                    block
                })
                .collect()
        };
        let x_embedded = embed(&x_bits, k);
        let mut y_expected_bits = embed(&y_bits, n);

        let mut y_expected = y.clone();
        lpn.compute([0u8; 16], &mut y_expected, &x);
        lpn.compute([0u8; 16], &mut y_expected_bits, &x_embedded);

        lpn.compute_with_bits([0u8; 16], &mut y, &mut y_bits, &x, &x_bits);

        assert_eq!(y, y_expected);
        for (i, block) in y_expected_bits.iter().enumerate() {
            assert_eq!((y_bits[i / 8] >> (i % 8)) & 1, block[0] & 1, "bit {i}");
        }
    }

    #[test]
    fn lpn_test() {
        use crate::{lpn::LpnEncoder, prg::Prg};

        let k = 16;
        let n = 200;
        let lpn = LpnEncoder::<10>::new(k);
        let mut x = vec![[0u8; 16]; k as usize];
        let mut y = vec![[0u8; 16]; n];
        let mut prg = Prg::new();
        prg.random_bytes(x.as_flattened_mut());
        prg.random_bytes(y.as_flattened_mut());
        let mut z = y.clone();

        lpn.compute_naive([0u8; 16], &mut y, &x);
        lpn.compute([0u8; 16], &mut z, &x);

        assert_eq!(y, z);
    }
}
