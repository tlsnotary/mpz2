//! Fixed-key AES cipher

use aes::Aes128Enc;
use cipher::{BlockCipherEncrypt, KeyInit};
use once_cell::sync::Lazy;

use crate::Block;

/// A fixed AES key (arbitrarily chosen).
pub const FIXED_KEY: [u8; 16] = [
    69, 42, 69, 42, 69, 42, 69, 42, 69, 42, 69, 42, 69, 42, 69, 42,
];

/// Fixed-key AES cipher
pub static FIXED_KEY_AES: Lazy<FixedKeyAes> = Lazy::new(|| FixedKeyAes {
    aes: Aes128Enc::new_from_slice(&FIXED_KEY).unwrap(),
});

/// Fixed-key AES cipher
pub struct FixedKeyAes {
    aes: Aes128Enc,
}

impl FixedKeyAes {
    /// Create a fixed-key AES cipher with a given key.
    pub fn new(key: [u8; 16]) -> Self {
        Self {
            aes: Aes128Enc::new(&key.into()),
        }
    }

    /// Tweakable circular correlation-robust hash function instantiated
    /// using fixed-key AES.
    ///
    /// See <https://eprint.iacr.org/2019/074> (Section 7.4)
    ///
    /// `π(π(x) ⊕ i) ⊕ π(x)`, where `π` is instantiated using fixed-key AES.
    #[inline]
    pub fn tccr(&self, tweak: Block, block: Block) -> Block {
        let mut h1 = block;
        self.aes.encrypt_block(h1.as_array_mut());

        let mut h2 = h1 ^ tweak;
        self.aes.encrypt_block(h2.as_array_mut());

        h1 ^ h2
    }

    /// Tweakable circular correlation-robust hash function instantiated
    /// using fixed-key AES.
    ///
    /// See <https://eprint.iacr.org/2019/074> (Section 7.4)
    ///
    /// `π(π(x) ⊕ i) ⊕ π(x)`, where `π` is instantiated using fixed-key AES.
    ///
    /// # Arguments
    ///
    /// * `tweaks` - The tweaks to use for each block in `blocks`.
    /// * `blocks` - The blocks to hash in-place.
    #[inline]
    pub fn tccr_many<const N: usize>(&self, tweaks: &[Block; N], blocks: &mut [Block; N]) {
        // Store π(x) in `blocks`
        self.aes.encrypt_blocks(Block::as_array_mut_slice(blocks));

        // Write π(x) ⊕ i into `buf`
        let mut buf: [Block; N] = std::array::from_fn(|i| blocks[i] ^ tweaks[i]);

        // Write π(π(x) ⊕ i) in `buf`
        self.aes.encrypt_blocks(Block::as_array_mut_slice(&mut buf));

        // Write π(π(x) ⊕ i) ⊕ π(x) into `blocks`
        blocks
            .iter_mut()
            .zip(buf.iter())
            .for_each(|(a, b)| *a ^= *b);
    }

    /// Correlation-robust hash function instantiated using fixed-key AES
    /// (cf. <https://eprint.iacr.org/2019/074>, §7.2).
    ///
    /// `π(x) ⊕ x`, where `π` is instantiated using fixed-key AES.
    #[inline]
    pub fn cr(&self, block: Block) -> Block {
        let mut h = block;
        self.aes.encrypt_block(h.as_array_mut());
        h ^ block
    }

    /// Correlation-robust hash function instantiated using fixed-key AES
    /// (cf. <https://eprint.iacr.org/2019/074>, §7.2).
    ///
    /// `π(x) ⊕ x`, where `π` is instantiated using fixed-key AES.
    ///
    /// # Arguments
    ///
    /// * `blocks` - The blocks to hash in-place.
    #[inline]
    pub fn cr_many<const N: usize>(&self, blocks: &mut [Block; N]) {
        let mut buf = *blocks;

        self.aes.encrypt_blocks(Block::as_array_mut_slice(&mut buf));

        blocks
            .iter_mut()
            .zip(buf.iter())
            .for_each(|(a, b)| *a ^= *b);
    }

    /// Circular correlation-robust hash function instantiated using fixed-key
    /// AES (cf.<https://eprint.iacr.org/2019/074>, §7.3).
    ///
    /// `π(σ(x)) ⊕ σ(x)`, where `π` is instantiated using fixed-key AES
    ///
    /// See [`Block::sigma`](Block::sigma) for more details on `σ`.
    #[inline]
    pub fn ccr(&self, block: Block) -> Block {
        self.cr(Block::sigma(block))
    }

    /// Circular correlation-robust hash function instantiated using fixed-key
    /// AES (cf.<https://eprint.iacr.org/2019/074>, §7.3).
    ///
    /// `π(σ(x)) ⊕ σ(x)`, where `π` is instantiated using fixed-key AES
    ///
    /// See [`Block::sigma`](Block::sigma) for more details on `σ`.
    ///
    /// # Arguments
    ///
    /// * `blocks` - The blocks to hash in-place.
    #[inline]
    pub fn ccr_many<const N: usize>(&self, blocks: &mut [Block; N]) {
        blocks.iter_mut().for_each(|b| *b = Block::sigma(*b));
        self.cr_many(blocks);
    }
}

/// A wrapper of aes, only for encryption.
#[derive(Clone)]
pub struct AesEncryptor(Aes128Enc);

impl AesEncryptor {
    /// Constant number of AES blocks, always set to 8.
    pub const AES_BLOCK_COUNT: usize = 8;

    /// Initiate an AesEncryptor instance with key.
    #[inline(always)]
    pub fn new(key: Block) -> Self {
        let _key: [u8; 16] = key.into();
        AesEncryptor(Aes128Enc::new_from_slice(&_key).unwrap())
    }

    /// Encrypt a block.
    #[inline(always)]
    pub fn encrypt_block(&self, mut blk: Block) -> Block {
        self.0.encrypt_block(blk.as_array_mut());
        blk
    }

    /// Encrypt a block in-place.
    pub fn encrypt_block_inplace(&self, blk: &mut Block) {
        self.0.encrypt_block(blk.as_array_mut());
    }

    /// Encrypt many blocks in-place.
    #[inline(always)]
    pub fn encrypt_many_blocks<const N: usize>(&self, blks: &mut [Block; N]) {
        self.0
            .encrypt_blocks(Block::as_array_mut_slice(blks.as_mut_slice()));
    }

    /// Encrypt slice of blocks in-place.
    #[inline]
    pub fn encrypt_blocks(&self, blks: &mut [Block]) {
        self.0.encrypt_blocks(Block::as_array_mut_slice(blks));
    }

    /// Encrypt many blocks with many keys.
    ///
    /// Each batch of NM blocks is encrypted by a corresponding AES key.
    ///
    /// **Only the first NK * NM blocks of blks are handled, the rest are
    /// ignored.**
    ///
    /// # Arguments
    ///
    /// * `keys` - A slice of keys used to encrypt the blocks.
    /// * `blks` - A slice of blocks to be encrypted.
    ///
    /// # Panics
    ///
    /// * If the length of `blks` is less than `NM * NK`.
    #[inline(always)]
    pub fn para_encrypt<const NK: usize, const NM: usize>(keys: &[Self; NK], blks: &mut [Block]) {
        assert!(blks.len() >= NM * NK);

        keys.iter()
            .zip(blks.as_chunks_mut::<NM>().0)
            .for_each(|(key, blks)| {
                key.encrypt_blocks(blks);
            });
    }
}

#[test]
fn aes_test() {
    let aes = AesEncryptor::new(Block::default());
    let aes1 = AesEncryptor::new(Block::ONES);

    let mut blks = [Block::default(); 4];
    blks[1] = Block::ONES;
    blks[3] = Block::ONES;
    AesEncryptor::para_encrypt::<2, 2>(&[aes, aes1], &mut blks);
    assert_eq!(
        blks,
        [
            Block::from((0x2E2B34CA59FA4C883B2C8AEFD44BE966_u128).to_le_bytes()),
            Block::from((0x4E668D3ED24773FA0A5A85EAC98C5B3F_u128).to_le_bytes()),
            Block::from((0x2CC9BF3845486489CD5F7D878C25F6A1_u128).to_le_bytes()),
            Block::from((0x79B93A19527051B230CF80B27C21BFBC_u128).to_le_bytes())
        ]
    );
}
