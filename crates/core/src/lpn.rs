//! Implement LPN with local linear code.
//! More specifically, a local linear code is a random boolean matrix with at
//! most D non-zero values in each row.

use crate::{Block, prp::Prp};
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
    /// A mask to optimize reduction operation.
    mask: u32,
}

impl<const D: usize> LpnEncoder<D> {
    /// Create a new LPN instance.
    pub fn new(k: u32) -> Self {
        let mut mask = 1;
        while mask < k {
            mask <<= 1;
            mask |= 0x1;
        }
        Self { k, mask }
    }

    /// Compute 4 rows as a batch, this is for the `compute` function.
    #[inline]
    fn compute_four_rows_indep(&self, y: &mut [Block], x: &[Block], pos: usize, prp: &Prp) {
        let mut cnt = 0u64;
        let mut index: [Block; D] = std::array::from_fn(|_| {
            let i = cnt;
            cnt += 1;
            Block::from(bytemuck::cast::<_, [u8; 16]>([pos as u64, i]))
        });

        prp.permute_many_blocks(&mut index);
        let index = bytemuck::cast_slice_mut::<_, u32>(&mut index);

        for (i, y) in y.iter_mut().enumerate().take(4) {
            for ind in index[i * D..(i + 1) * D].iter_mut() {
                *ind &= self.mask;
                *ind = if *ind >= self.k { *ind - self.k } else { *ind };

                *y ^= x[*ind as usize];
            }
        }
    }

    #[inline]
    fn compute_one_row(&self, y: &mut [Block], x: &[Block], pos: usize, prp: &Prp) {
        // (D + 4 - 1) / 4
        let block_size = D.div_ceil(4);
        let mut index = (0..block_size)
            .map(|i| Block::from(bytemuck::cast::<_, [u8; 16]>([pos as u64, i as u64])))
            .collect::<Vec<Block>>();
        prp.permute_block_inplace(&mut index);
        let index = bytemuck::cast_slice_mut::<_, u32>(&mut index);

        for ind in index.iter_mut().take(D) {
            *ind &= self.mask;
            *ind = if *ind >= self.k { *ind - self.k } else { *ind };
            y[pos] ^= x[*ind as usize];
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
    pub fn compute(&self, seed: Block, y: &mut [Block], x: &[Block]) {
        assert_eq!(x.len() as u32, self.k);
        assert!(x.len() >= D);
        let prp = Prp::new(seed);
        let size = y.len() - (y.len() % 4);

        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")]{
                use rayon::prelude::*;

                let iter = y.par_chunks_exact_mut(4).enumerate();
            }else{
                let iter = y.chunks_exact_mut(4).enumerate();
            }
        }

        iter.for_each(|(i, y)| {
            self.compute_four_rows_indep(y, x, i * 4, &prp);
        });

        for i in size..y.len() {
            self.compute_one_row(y, x, i, &prp);
        }
    }
}

/// LPN type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LpnType {
    /// LPN with a uniform error vector.
    Uniform,
    /// LPN with an error vector that has non-zero entries distributed
    /// regularly.
    Regular,
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

/// Samples indices for non-zero entries in the error vector.
///
/// # Panics
///
/// Panics if `ty` is `Regular` and `len` is not a multiple of `count`.
///
/// # Arguments
///
/// * `rng` - Random number generator.
/// * `ty` - LPN type.
/// * `len` - Length of the error vector.
/// * `count` - Hamming weight.
pub fn sample_error_indices<R: Rng>(
    rng: &mut R,
    ty: LpnType,
    len: usize,
    count: usize,
) -> Vec<usize> {
    match ty {
        LpnType::Uniform => rand::seq::index::sample(rng, len, count).into_vec(),
        LpnType::Regular => {
            assert_eq!(len % count, 0);
            let step = len / count;
            (0..count)
                .map(|i| rng.random_range(i * step..(i + 1) * step))
                .collect()
        }
    }
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
    use crate::{Block, lpn::LpnEncoder, prp::Prp};

    impl<const D: usize> LpnEncoder<D> {
        #[allow(dead_code)]
        fn compute_four_rows_non_indep(&self, y: &mut [Block], x: &[Block], pos: usize, prp: &Prp) {
            let mut cnt = 0u64;
            let mut index = [0; D].map(|_| {
                let i: u64 = cnt;
                cnt += 1;
                Block::from(bytemuck::cast::<_, [u8; 16]>([pos as u64, i]))
            });

            prp.permute_many_blocks(&mut index);
            let index: &mut [u32] = bytemuck::cast_slice_mut::<_, u32>(&mut index);

            for (i, y) in y[pos..].iter_mut().enumerate().take(4) {
                for ind in index[i * D..(i + 1) * D].iter_mut() {
                    *ind &= self.mask;
                    *ind = if *ind >= self.k { *ind - self.k } else { *ind };

                    *y ^= x[*ind as usize];
                }
            }
        }

        #[allow(dead_code)]
        pub(crate) fn compute_naive(&self, seed: Block, y: &mut [Block], x: &[Block]) {
            assert_eq!(x.len() as u32, self.k);
            assert!(x.len() >= D);
            let prp = Prp::new(seed);
            let batch_size = y.len() / 4;

            for i in 0..batch_size {
                self.compute_four_rows_non_indep(y, x, i * 4, &prp);
            }

            for i in batch_size * 4..y.len() {
                self.compute_one_row(y, x, i, &prp);
            }
        }
    }

    #[test]
    fn lpn_test() {
        use crate::{Block, lpn::LpnEncoder, prg::Prg};

        let k = 20;
        let n = 200;
        let lpn = LpnEncoder::<10>::new(k);
        let mut x = vec![Block::ONES; k as usize];
        let mut y = vec![Block::ONES; n];
        let mut prg = Prg::new();
        prg.random_blocks(&mut x);
        prg.random_blocks(&mut y);
        let mut z = y.clone();

        lpn.compute_naive(Block::ZERO, &mut y, &x);
        lpn.compute(Block::ZERO, &mut z, &x);

        assert_eq!(y, z);
    }
}
