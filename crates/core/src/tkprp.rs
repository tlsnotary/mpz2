//! Implement the two-key PRG as G(k) = PRF_seed0(k)\xor k || PRF_seed1(k)\xor k
//! Refer to (<https://www.usenix.org/system/files/conference/nsdi17/nsdi17-wang-frank.pdf>, Page 8)

use crate::{Block, aes::AesEncryptor};

/// Struct of two-key prp.
/// This implementation is adapted from EMP toolkit.
pub struct TwoKeyPrp([AesEncryptor; 2]);

impl TwoKeyPrp {
    /// Creates a new instance of TwoKeyPrp.
    #[inline(always)]
    pub fn new(seeds: [Block; 2]) -> Self {
        Self([AesEncryptor::new(seeds[0]), AesEncryptor::new(seeds[1])])
    }

    /// Expands inputs to the destination slice.
    ///
    /// For each input `x`, writes `aes0(x) ^ x` to `dest[2i]` and
    /// `aes1(x) ^ x` to `dest[2i+1]`.
    ///
    /// # Panics
    ///
    /// Panics if the destination slice is not twice the length of the input
    /// slice.
    ///
    /// # Arguments
    ///
    /// * `inputs` - The input blocks to expand with the two-key PRP.
    /// * `dest` - The destination slice to write the expanded blocks.
    pub fn expand(&self, inputs: &[Block], dest: &mut [Block]) {
        assert_eq!(
            dest.len(),
            2 * inputs.len(),
            "dest should have twice the length of inputs"
        );

        const CHUNK: usize = 64;

        for (in_chunk, out_chunk) in inputs.chunks(CHUNK).zip(dest.chunks_mut(2 * CHUNK)) {
            let m = in_chunk.len();
            let mut s0 = [Block::ZERO; CHUNK];
            let mut s1 = [Block::ZERO; CHUNK];
            s0[..m].copy_from_slice(in_chunk);
            s1[..m].copy_from_slice(in_chunk);
            self.0[0].encrypt_blocks(&mut s0[..m]);
            self.0[1].encrypt_blocks(&mut s1[..m]);
            for (i, &x) in in_chunk.iter().enumerate() {
                out_chunk[2 * i] = s0[i] ^ x;
                out_chunk[2 * i + 1] = s1[i] ^ x;
            }
        }
    }
}
