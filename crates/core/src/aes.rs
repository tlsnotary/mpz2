//! Fixed-key AES cipher

use aes::Aes128Enc;
use cipher::{BlockCipherEncrypt, KeyInit};
use hybrid_array::{Array, typenum::consts::U16};
use once_cell::sync::Lazy;

/// A fixed AES key (arbitrarily chosen).
pub const FIXED_KEY: [u8; 16] = [
    69, 42, 69, 42, 69, 42, 69, 42, 69, 42, 69, 42, 69, 42, 69, 42,
];

/// Fixed-key AES cipher
pub static FIXED_KEY_AES: Lazy<FixedKeyAes> = Lazy::new(|| FixedKeyAes {
    aes: Aes128Enc::new(&FIXED_KEY.into()),
});

/// XOR of two 16-byte blocks.
#[inline(always)]
fn xor(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    (u128::from_ne_bytes(a) ^ u128::from_ne_bytes(b)).to_ne_bytes()
}

/// Reinterprets a mutable block as the AES cipher's array type.
#[inline(always)]
fn as_array(block: &mut [u8; 16]) -> &mut Array<u8, U16> {
    block.into()
}

/// Reinterprets a mutable slice of blocks as the AES cipher's array type.
#[inline(always)]
fn as_array_slice(blocks: &mut [[u8; 16]]) -> &mut [Array<u8, U16>] {
    Array::cast_slice_from_core_mut(blocks)
}

/// Linear orthomorphism `σ(x_hi || x_lo) = (x_hi ⊕ x_lo) || x_hi`.
///
/// See <https://eprint.iacr.org/2019/074> (Section 7.3), instantiation (ii).
///
/// The halves are interpreted in little-endian order so the mapping is
/// platform independent.
#[inline(always)]
fn sigma(block: [u8; 16]) -> [u8; 16] {
    const HI: u128 = ((1u128 << 64) - 1) << 64;

    let x = u128::from_le_bytes(block);
    // Swapping the halves moves `x_hi` into the low half, and XORing the
    // masked value folds `x_hi` into the high half.
    (x.rotate_left(64) ^ (x & HI)).to_le_bytes()
}

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

    /// Circular correlation-robust hash function instantiated using fixed-key
    /// AES.
    ///
    /// See <https://eprint.iacr.org/2019/074> (Section 7.3)
    ///
    /// `π(σ(x)) ⊕ σ(x)`, where `π` is instantiated using fixed-key AES and `σ`
    /// is a linear orthomorphism.
    ///
    /// The result is written back into `block`.
    #[inline]
    pub fn ccr(&self, block: &mut [u8; 16]) {
        *block = sigma(*block);
        let mut h = *block;
        self.aes.encrypt_block(as_array(&mut h));
        *block = xor(*block, h);
    }

    /// Circular correlation-robust hash function instantiated using fixed-key
    /// AES, writing the hash of each block in `src` to `dst`.
    ///
    /// See [`FixedKeyAes::ccr`].
    ///
    /// Hashes are computed in batches large enough to saturate the parallel
    /// width of the AES backend.
    ///
    /// # Panics
    ///
    /// Panics if `src` and `dst` have different lengths.
    #[inline]
    pub fn ccr_blocks_to(&self, src: &[[u8; 16]], dst: &mut [[u8; 16]]) {
        assert_eq!(src.len(), dst.len(), "src and dst must have equal length");

        const N: usize = 64;

        let mut buf = [[0u8; 16]; N];
        for (src, dst) in src.chunks(N).zip(dst.chunks_mut(N)) {
            let m = src.len();
            for (s, d) in src.iter().zip(dst.iter_mut()) {
                *d = sigma(*s);
            }
            buf[..m].copy_from_slice(&dst[..m]);
            self.aes.encrypt_blocks(as_array_slice(&mut buf[..m]));
            for (d, h) in dst.iter_mut().zip(&buf) {
                *d = xor(*d, *h);
            }
        }
    }

    /// Tweakable circular correlation-robust hash function instantiated
    /// using fixed-key AES.
    ///
    /// See <https://eprint.iacr.org/2019/074> (Section 7.4)
    ///
    /// `π(π(x) ⊕ i) ⊕ π(x)`, where `π` is instantiated using fixed-key AES.
    ///
    /// The result is written back into `block`.
    #[inline]
    pub fn tccr(&self, tweak: [u8; 16], block: &mut [u8; 16]) {
        // h1 = π(x)
        self.aes.encrypt_block(as_array(block));
        let h1 = *block;

        // h2 = π(π(x) ⊕ i)
        let mut h2 = xor(h1, tweak);
        self.aes.encrypt_block(as_array(&mut h2));

        // π(π(x) ⊕ i) ⊕ π(x)
        *block = xor(h1, h2);
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
    pub fn tccr_many<const N: usize>(&self, tweaks: &[[u8; 16]; N], blocks: &mut [[u8; 16]; N]) {
        // Store π(x) in `blocks`
        self.aes.encrypt_blocks(as_array_slice(blocks));

        // Write π(x) ⊕ i into `buf`
        let mut buf: [[u8; 16]; N] = std::array::from_fn(|i| xor(blocks[i], tweaks[i]));

        // Write π(π(x) ⊕ i) in `buf`
        self.aes.encrypt_blocks(as_array_slice(&mut buf));

        // Write π(π(x) ⊕ i) ⊕ π(x) into `blocks`
        blocks
            .iter_mut()
            .zip(buf.iter())
            .for_each(|(a, b)| *a = xor(*a, *b));
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
    pub fn new(key: [u8; 16]) -> Self {
        AesEncryptor(Aes128Enc::new(&key.into()))
    }

    /// Encrypt a block in-place.
    #[inline(always)]
    pub fn encrypt_block(&self, blk: &mut [u8; 16]) {
        self.0.encrypt_block(as_array(blk));
    }

    /// Encrypt many blocks in-place.
    #[inline(always)]
    pub fn encrypt_many_blocks<const N: usize>(&self, blks: &mut [[u8; 16]; N]) {
        self.0.encrypt_blocks(as_array_slice(blks));
    }

    /// Encrypt slice of blocks in-place.
    #[inline]
    pub fn encrypt_blocks(&self, blks: &mut [[u8; 16]]) {
        self.0.encrypt_blocks(as_array_slice(blks));
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
    pub fn para_encrypt<const NK: usize, const NM: usize>(
        keys: &[Self; NK],
        blks: &mut [[u8; 16]],
    ) {
        assert!(blks.len() >= NM * NK);

        keys.iter()
            .zip(blks.as_chunks_mut::<NM>().0)
            .for_each(|(key, blks)| {
                key.encrypt_blocks(blks);
            });
    }
}

#[test]
fn ccr_blocks_to_test() {
    // Long enough to cover both a full batch and a remainder.
    let blocks: Vec<[u8; 16]> = (0u8..67).map(|i| [i; 16]).collect();
    let expected: Vec<[u8; 16]> = blocks
        .iter()
        .map(|block| {
            let mut block = *block;
            FIXED_KEY_AES.ccr(&mut block);
            block
        })
        .collect();

    let mut hashes = vec![[0u8; 16]; blocks.len()];
    FIXED_KEY_AES.ccr_blocks_to(&blocks, &mut hashes);
    assert_eq!(hashes, expected);
}

#[test]
fn aes_test() {
    let aes = AesEncryptor::new([0u8; 16]);
    let aes1 = AesEncryptor::new([0xffu8; 16]);

    let mut blks = [[0u8; 16]; 4];
    blks[1] = [0xff; 16];
    blks[3] = [0xff; 16];
    AesEncryptor::para_encrypt::<2, 2>(&[aes, aes1], &mut blks);
    assert_eq!(
        blks,
        [
            0x2E2B34CA59FA4C883B2C8AEFD44BE966_u128.to_le_bytes(),
            0x4E668D3ED24773FA0A5A85EAC98C5B3F_u128.to_le_bytes(),
            0x2CC9BF3845486489CD5F7D878C25F6A1_u128.to_le_bytes(),
            0x79B93A19527051B230CF80B27C21BFBC_u128.to_le_bytes()
        ]
    );
}
