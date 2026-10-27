//! An implementation of Pseudo Random Permutation (PRP) based on AES.

use crate::aes::AesEncryptor;

/// Pseudo Random Permutation (PRP) based on AES.
pub struct Prp(AesEncryptor);

impl Prp {
    /// Creates a new instance of Prp.
    #[inline(always)]
    pub fn new(seed: [u8; 16]) -> Self {
        Prp(AesEncryptor::new(seed))
    }

    /// Permute many blocks.
    #[inline(always)]
    pub fn permute_many_blocks<const N: usize>(&self, blks: &mut [[u8; 16]; N]) {
        self.0.encrypt_many_blocks(blks)
    }

    /// Permute block slice.
    #[inline(always)]
    pub fn permute_block_inplace(&self, blks: &mut [[u8; 16]]) {
        self.0.encrypt_blocks(blks);
    }
}
