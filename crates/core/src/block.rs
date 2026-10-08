//! A block of 128 bits and its operations.

use bytemuck::{Pod, Zeroable};
use clmul::Clmul;
use core::ops::{BitAnd, BitAndAssign, BitXor, BitXorAssign};
use hybrid_array::{Array, typenum::consts::U16};
use itybity::{BitIterable, BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use rand::{CryptoRng, Rng, RngExt, distr::StandardUniform, prelude::Distribution};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display},
    slice::from_raw_parts,
};

/// A block of 128 bits
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Serialize, Deserialize, Pod, Zeroable)]
pub struct Block([u8; 16]);

impl Block {
    /// The length of a block in bytes
    pub const LEN: usize = 16;
    /// A zero block
    pub const ZERO: Self = Self([0; 16]);
    /// A one block
    pub const ONE: Self = Self([1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    /// A block with all bits set to 1
    pub const ONES: Self = Self([0xff; 16]);
    /// A length 2 array of zero and one blocks
    pub const SELECT_MASK: [Self; 2] = [Self::ZERO, Self::ONES];
    /// A length 128 vector where each block has a single bit set to 1.
    pub const MONOMIAL: [Block; 128] = {
        let mut v = [Block::ZERO; 128];
        let mut i = 0;
        while i < 128 {
            v[i].0[i / 8] = 1 << (i % 8);
            i += 1;
        }
        v
    };

    /// Create a new block
    #[inline]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the block encoded as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the byte representation of the block
    #[inline]
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Generate a random block using the provided RNG
    #[inline]
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::new(rng.random())
    }

    /// Generate a random array of blocks using the provided RNG
    #[inline]
    pub fn random_array<const N: usize, R: Rng + CryptoRng>(rng: &mut R) -> [Self; N] {
        std::array::from_fn(|_| rng.random::<[u8; 16]>().into())
    }

    /// Generate a random vector of blocks using the provided RNG
    #[inline]
    pub fn random_vec<R: Rng + CryptoRng + ?Sized>(rng: &mut R, n: usize) -> Vec<Self> {
        (0..n).map(|_| rng.random::<[u8; 16]>().into()).collect()
    }

    /// Carry-less multiplication of two blocks, without the reduction step.
    #[inline]
    pub fn clmul(self, other: Self) -> (Self, Self) {
        let (a, b) = Clmul::new(&self.0).clmul(Clmul::new(&other.0));
        (Self::new(a.into()), Self::new(b.into()))
    }

    #[inline]
    /// Reduces the polynomial represented in bits modulo the GCM polynomial
    /// x^128 + x^7 + x^2 + x + 1. `x` and `y` are resp. upper and lower
    /// bits of the polynomial.
    pub fn reduce_gcm(x: Self, y: Self) -> Self {
        let r = Clmul::reduce_gcm(Clmul::new(&x.0), Clmul::new(&y.0));
        Self::new(r.into())
    }

    /// The multiplication of two Galois field elements.
    #[inline]
    pub fn gfmul(self, x: Self) -> Self {
        let (a, b) = self.clmul(x);
        Block::reduce_gcm(a, b)
    }

    /// Compute the inner product of two block vectors, without reducing the
    /// polynomial.
    #[inline]
    pub fn inn_prdt_no_red(a: &[Block], b: &[Block]) -> (Block, Block) {
        assert_eq!(a.len(), b.len());
        a.iter()
            .zip(b.iter())
            .fold((Block::ZERO, Block::ZERO), |acc, (x, y)| {
                let t = x.clmul(*y);
                (t.0 ^ acc.0, t.1 ^ acc.1)
            })
    }

    /// Compute the inner product of two block vectors.
    #[inline]
    pub fn inn_prdt_red(a: &[Block], b: &[Block]) -> Block {
        let (x, y) = Block::inn_prdt_no_red(a, b);
        Block::reduce_gcm(x, y)
    }

    /// Reverses the bits of the block
    #[inline]
    pub fn reverse_bits(self) -> Self {
        Self(u128::from_le_bytes(self.0).reverse_bits().to_le_bytes())
    }

    /// Sets the least significant bit of the block
    #[inline]
    pub fn set_lsb(&mut self, value: bool) {
        self.0[0] = (self.0[0] & 0xfe) | value as u8;
    }

    /// XORs the least significant bit of the block with the given value.
    #[inline]
    pub fn xor_lsb(&mut self, bit: bool) {
        self.0[0] ^= bit as u8;
    }

    /// Returns the least significant bit of the block
    #[inline]
    pub fn lsb(&self) -> bool {
        (self.0[0] & 1) == 1
    }

    /// Let `x0` and `x1` be the lower and higher halves of `x`, respectively.
    /// This function compute ``sigma( x = x0 || x1 ) = x1 || (x0 xor x1)``.
    #[inline(always)]
    pub fn sigma(a: Self) -> Self {
        let mut x: [u64; 2] = bytemuck::cast(a);
        x[0] ^= x[1];
        bytemuck::cast([x[1], x[0]])
    }

    /// Converts a slice of blocks to a slice of bytes.
    pub fn as_flattened_bytes(slice: &[Self]) -> &[u8] {
        // This is equivalent to `<[[u8; 16]]>::as_flattened`

        // SAFETY: `slice.len() * Block::LEN` cannot overflow because `slice` is
        // already in the address space.
        let len = unsafe { slice.len().unchecked_mul(Self::LEN) };
        // SAFETY: `[u8]` is layout-identical to `[u8; 16]` of which block is a
        // newtype.
        unsafe { from_raw_parts(slice.as_ptr().cast(), len) }
    }

    /// Converts a slice of block arrays to a slice of bytes.
    pub fn array_as_flattened_bytes<const N: usize>(slice: &[[Self; N]]) -> &[u8] {
        // This is equivalent to `<[[u8; 16 * N]]>::as_flattened`

        // SAFETY: `slice.len() * N * Block::LEN` cannot overflow because
        // `slice` is already in the address space.
        let len = unsafe { slice.len().unchecked_mul(N * Self::LEN) };
        // SAFETY: `[u8]` is layout-identical to `[u8; 16]` of which block is a
        // newtype.
        unsafe { from_raw_parts(slice.as_ptr().cast(), len) }
    }

    /// Converts a block to a [`Array<u8,
    /// U16>`] from the [`hybrid-array`](https://docs.rs/hybrid-array/latest/hybrid_array/) crate.
    #[allow(dead_code)]
    pub(crate) fn as_array(&self) -> &Array<u8, U16> {
        (&self.0).into()
    }

    /// Converts a mutable block to a mutable [`Array<u8,
    /// U16>`] from the [`hybrid-array`](https://docs.rs/hybrid-array/latest/hybrid_array/) crate.
    pub(crate) fn as_array_mut(&mut self) -> &mut Array<u8, U16> {
        (&mut self.0).into()
    }

    /// Converts a slice of blocks to a slice of [`Array<u8,
    /// U16>`]from the [`hybrid-array`](https://docs.rs/hybrid-array/latest/hybrid_array/) crate.
    #[allow(dead_code)]
    pub(crate) fn as_array_slice(slice: &[Self]) -> &[Array<u8, U16>] {
        unsafe { std::mem::transmute(slice) }
    }

    /// Converts a mutable slice of blocks to a mutable slice of
    ///  from the [`hybrid-array`](https://docs.rs/hybrid-array/latest/hybrid_array/) crate.
    pub(crate) fn as_array_mut_slice(slice: &mut [Self]) -> &mut [Array<u8, U16>] {
        unsafe { std::mem::transmute(slice) }
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Block(")?;
        for byte in self.0.iter() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")?;
        Ok(())
    }
}

impl AsRef<[u8]> for Block {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A trait for converting a type to blocks
pub trait BlockSerialize {
    /// The block representation of the type
    type Serialized: std::fmt::Debug + Clone + Copy + Send + Sync + 'static;

    /// Convert the type to blocks
    fn to_blocks(self) -> Self::Serialized;

    /// Convert the blocks to the type
    fn from_blocks(blocks: Self::Serialized) -> Self;
}

impl BitLength for Block {
    const BITS: usize = 128;
}

impl GetBit<Lsb0> for Block {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Lsb0>::get_bit(&self.0[index / 8], index % 8)
    }
}

impl GetBit<Msb0> for Block {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Msb0>::get_bit(&self.0[15 - (index / 8)], index % 8)
    }
}

impl BitIterable for Block {}

impl FromBitIterator for Block {
    fn from_lsb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Block(<[u8; 16]>::from_lsb0_iter(iter))
    }

    fn from_msb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Block(<[u8; 16]>::from_msb0_iter(iter))
    }
}

impl From<[u8; 16]> for Block {
    #[inline]
    fn from(bytes: [u8; 16]) -> Self {
        Block::new(bytes)
    }
}

impl<'a> From<&'a [u8; 16]> for &'a Block {
    fn from(bytes: &'a [u8; 16]) -> Self {
        bytemuck::cast_ref(bytes)
    }
}

impl<'a> TryFrom<&'a [u8]> for Block {
    type Error = <[u8; 16] as TryFrom<&'a [u8]>>::Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        <[u8; 16]>::try_from(value).map(Self::from)
    }
}

impl From<Block> for Array<u8, U16> {
    #[inline]
    fn from(b: Block) -> Self {
        b.0.into()
    }
}

impl<'a> From<&'a Block> for &'a Array<u8, U16> {
    #[inline]
    fn from(b: &'a Block) -> Self {
        (&b.0).into()
    }
}

impl From<Array<u8, U16>> for Block {
    #[inline]
    fn from(b: Array<u8, U16>) -> Self {
        Block::new(b.into())
    }
}

impl<'a> From<&'a Array<u8, U16>> for &'a Block {
    #[inline]
    fn from(b: &'a Array<u8, U16>) -> Self {
        let b: &'a [u8; 16] = b.as_ref();
        b.into()
    }
}

impl From<Block> for [u8; 16] {
    #[inline]
    fn from(b: Block) -> Self {
        b.0
    }
}

impl<'a> From<&'a Block> for &'a [u8; 16] {
    #[inline]
    fn from(b: &'a Block) -> Self {
        &b.0
    }
}

impl BitXor for Block {
    type Output = Self;

    #[inline]
    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.bitxor_assign(rhs);
        self
    }
}

impl BitXor<&Block> for Block {
    type Output = Block;

    fn bitxor(mut self, rhs: &Self) -> Self::Output {
        self.bitxor_assign(rhs);
        self
    }
}

impl BitXor<Block> for &Block {
    type Output = Block;

    fn bitxor(self, rhs: Block) -> Self::Output {
        *self ^ rhs
    }
}

impl BitXor<&Block> for &Block {
    type Output = Block;

    fn bitxor(self, rhs: &Block) -> Self::Output {
        *self ^ rhs
    }
}

impl BitXorAssign<&Block> for Block {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.0[15] ^= rhs.0[15];
        self.0[14] ^= rhs.0[14];
        self.0[13] ^= rhs.0[13];
        self.0[12] ^= rhs.0[12];
        self.0[11] ^= rhs.0[11];
        self.0[10] ^= rhs.0[10];
        self.0[9] ^= rhs.0[9];
        self.0[8] ^= rhs.0[8];
        self.0[7] ^= rhs.0[7];
        self.0[6] ^= rhs.0[6];
        self.0[5] ^= rhs.0[5];
        self.0[4] ^= rhs.0[4];
        self.0[3] ^= rhs.0[3];
        self.0[2] ^= rhs.0[2];
        self.0[1] ^= rhs.0[1];
        self.0[0] ^= rhs.0[0];
    }
}

impl BitXorAssign for Block {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.bitxor_assign(&rhs);
    }
}

impl BitAnd for Block {
    type Output = Self;

    #[inline]
    fn bitand(mut self, rhs: Self) -> Self::Output {
        self.bitand_assign(&rhs);
        self
    }
}

impl BitAnd<&Block> for Block {
    type Output = Block;

    fn bitand(mut self, rhs: &Self) -> Self::Output {
        self.bitand_assign(rhs);
        self
    }
}

impl BitAnd<Block> for &Block {
    type Output = Block;

    fn bitand(self, rhs: Block) -> Self::Output {
        *self & rhs
    }
}

impl BitAnd<&Block> for &Block {
    type Output = Block;

    fn bitand(self, rhs: &Block) -> Self::Output {
        *self & rhs
    }
}

impl BitAndAssign<&Block> for Block {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: &Self) {
        self.0[15] &= rhs.0[15];
        self.0[14] &= rhs.0[14];
        self.0[13] &= rhs.0[13];
        self.0[12] &= rhs.0[12];
        self.0[11] &= rhs.0[11];
        self.0[10] &= rhs.0[10];
        self.0[9] &= rhs.0[9];
        self.0[8] &= rhs.0[8];
        self.0[7] &= rhs.0[7];
        self.0[6] &= rhs.0[6];
        self.0[5] &= rhs.0[5];
        self.0[4] &= rhs.0[4];
        self.0[3] &= rhs.0[3];
        self.0[2] &= rhs.0[2];
        self.0[1] &= rhs.0[1];
        self.0[0] &= rhs.0[0];
    }
}

impl Distribution<Block> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block {
        Block::new(rng.random())
    }
}

impl AsMut<[u8]> for Block {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use itybity::ToBits;

    use super::*;

    #[test]
    fn test_set_lsb() {
        let mut b = Block::ZERO;
        b.set_lsb(true);
        assert!(b.lsb());

        b.set_lsb(false);
        assert!(!b.lsb());
    }

    #[test]
    fn test_lsb() {
        let a = Block::new([0; 16]);
        assert!(!a.lsb());

        let mut one = [0; 16];
        one[0] = 1;

        let a = Block::new(one);
        assert!(a.lsb());

        let mut two = [0; 16];
        two[0] = 2;

        let a = Block::new(two);
        assert!(!a.lsb());

        let mut three = [0; 16];
        three[0] = 3;

        let a = Block::new(three);
        assert!(a.lsb());
    }

    #[test]
    fn test_reverse_bits() {
        let a = Block::new([42; 16]);

        let mut expected_bits = a.to_lsb0_vec();
        expected_bits.reverse();

        assert_eq!(a.reverse_bits().to_lsb0_vec(), expected_bits);
    }

    #[test]
    fn inn_prdt_test() {
        use rand::{RngExt, SeedableRng};
        use rand_chacha::ChaCha12Rng;
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        const SIZE: usize = 1000;
        let mut a = Vec::new();
        let mut b = Vec::new();
        let mut c = (Block::ZERO, Block::ZERO);
        let mut d = Block::ZERO;
        for i in 0..SIZE {
            let r: [u8; 16] = rng.random();
            a.push(Block::from(r));
            let r: [u8; 16] = rng.random();
            b.push(Block::from(r));

            let z = a[i].clmul(b[i]);
            c.0 ^= z.0;
            c.1 ^= z.1;

            let x = a[i].gfmul(b[i]);
            d ^= x;
        }

        assert_eq!(c, Block::inn_prdt_no_red(&a, &b));
        assert_eq!(d, Block::inn_prdt_red(&a, &b));
    }

    #[test]
    fn sigma_test() {
        use rand::{RngExt, SeedableRng};
        use rand_chacha::ChaCha12Rng;
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let mut x: [u8; 16] = rng.random();
        let bx = Block::sigma(Block::from(x));
        let (xl, xr) = x.split_at_mut(8);

        for (x, y) in xl.iter_mut().zip(xr.iter_mut()) {
            *x ^= *y;
            std::mem::swap(x, y);
        }
        let expected_sigma = Block::from(x);
        assert_eq!(bx, expected_sigma);
    }

    #[test]
    fn test_monomial_vector() {
        for i in 0..128 {
            assert_eq!(u128::from_le_bytes(Block::MONOMIAL[i].0), 1 << i);
        }
    }
}
