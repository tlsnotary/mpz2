//! This module implements the extension field GF(2^128).

use hybrid_array::{
    Array,
    typenum::{U16, U128},
};
use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use rand::{distr::StandardUniform, prelude::Distribution};
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Neg, Sub};

use mpz_core::Block;

use crate::{Field, FieldError};

/// A type for holding field elements of Gf(2^128).
#[derive(
    Copy,
    Clone,
    Default,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
#[repr(transparent)]
pub struct Gf2_128(pub(crate) u128);

opaque_debug::implement!(Gf2_128);

impl Gf2_128 {
    /// Creates a new field element from a u128,
    /// mapping the integer to the corresponding polynomial.
    ///
    /// For example, 5u128 is mapped to the polynomial `1 + x^2`.
    pub const fn new(input: u128) -> Self {
        Gf2_128(input)
    }

    /// Returns the field element as a u128.
    pub const fn to_inner(self) -> u128 {
        self.0
    }
}

impl From<Gf2_128> for Block {
    fn from(value: Gf2_128) -> Self {
        Block::new(value.0.to_be_bytes())
    }
}

impl From<Block> for Gf2_128 {
    fn from(block: Block) -> Self {
        Gf2_128(u128::from_be_bytes(block.to_bytes()))
    }
}

impl TryFrom<Array<u8, U16>> for Gf2_128 {
    type Error = FieldError;

    fn try_from(value: Array<u8, U16>) -> Result<Self, Self::Error> {
        let inner: [u8; 16] = value.into();

        Ok(Gf2_128(u128::from_be_bytes(inner)))
    }
}

impl Distribution<Gf2_128> for StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Gf2_128 {
        Gf2_128(self.sample(rng))
    }
}

impl Add for Gf2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Sub for Gf2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Mul for Gf2_128 {
    type Output = Self;

    /// Galois field multiplication of two 128-bit blocks reduced by the GCM
    /// polynomial.
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        // See NIST SP 800-38D, Recommendation for Block Cipher Modes of
        // Operation: Galois/Counter Mode (GCM) and GMAC.
        //
        // Note that the NIST specification uses a different representation of
        // the polynomial, where the bits are reversed. This "bit
        // reflection" is discussed in Intel® Carry-Less Multiplication
        // Instruction and its Usage for Computing the GCM Mode.
        //
        // The irreducible polynomial is the same, ie `x^128 + x^7 + x^2 + x +
        // 1`.
        Gf2_128(gf128_mul(self.0, rhs.0))
    }
}

impl Neg for Gf2_128 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Field for Gf2_128 {
    type BitSize = U128;

    type ByteSize = U16;

    fn zero() -> Self {
        Self::new(0)
    }

    fn one() -> Self {
        Self::new(1)
    }

    fn two_pow(rhs: u32) -> Self {
        Self(1 << rhs)
    }

    /// Galois field inversion of 128-bit block.
    fn inverse(self) -> Option<Self> {
        if self == Self::zero() {
            return None;
        }
        Some(Gf2_128(gf128_inverse(self.0)))
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }

    #[inline]
    fn inner_product_chunk(a: &[Self], b: &[Self]) -> Self {
        Gf2_128(gf128_inner_product(a, b))
    }

    #[inline]
    fn square(self) -> Self {
        Gf2_128(gf128_square(self.0))
    }
}

cfg_select! {
    all(target_arch = "x86_64", target_feature = "pclmulqdq") => {
        mod x86;
        use x86 as backend;
    }
    all(target_arch = "wasm32", target_feature = "simd128") => {
        mod wasm;
        use wasm as backend;
    }
    _ => {
        mod soft;
        use soft as backend;
    }
}

#[inline(always)]
fn gf128_mul(a: u128, b: u128) -> u128 {
    backend::mul(a, b)
}

#[inline(always)]
fn gf128_inner_product(a: &[Gf2_128], b: &[Gf2_128]) -> u128 {
    backend::inner_product(a, b)
}

#[inline(always)]
fn gf128_inverse(a: u128) -> u128 {
    backend::inverse(a)
}

#[inline(always)]
fn gf128_square(a: u128) -> u128 {
    backend::square(a)
}

impl BitLength for Gf2_128 {
    const BITS: usize = 128;
}

impl GetBit<Lsb0> for Gf2_128 {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Lsb0>::get_bit(&self.0, index)
    }
}

impl GetBit<Msb0> for Gf2_128 {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Msb0>::get_bit(&self.0, index)
    }
}

impl FromBitIterator for Gf2_128 {
    fn from_lsb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Self(u128::from_lsb0_iter(iter))
    }

    fn from_msb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Self(u128::from_msb0_iter(iter))
    }
}

#[cfg(test)]
mod tests {
    use super::Gf2_128;
    use crate::{
        Field,
        tests::{
            test_field_axioms_random, test_field_basic, test_field_bit_ops_lsb0,
            test_field_bit_ops_msb0, test_field_compute_product_repeated, test_field_inner_product,
            test_field_square,
        },
    };
    #[test]
    fn test_gf2_128_basic() {
        test_field_basic::<Gf2_128>();
        assert_eq!(Gf2_128::new(0), Gf2_128::zero());
        assert_eq!(Gf2_128::new(1), Gf2_128::one());
    }

    #[test]
    fn test_gf2_128_compute_product_repeated() {
        test_field_compute_product_repeated::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_inner_product() {
        test_field_inner_product::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_axioms_random() {
        test_field_axioms_random::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_square() {
        test_field_square::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_bit_ops() {
        test_field_bit_ops_lsb0::<Gf2_128>();
        test_field_bit_ops_msb0::<Gf2_128>();
    }

    #[test]
    #[should_panic(expected = "inner_product: slice length mismatch")]
    fn test_gf2_128_inner_product_length_mismatch() {
        let a = [Gf2_128::new(1), Gf2_128::new(1)];
        let b = [Gf2_128::new(1)];
        let _ = Gf2_128::inner_product(&a, &b);
    }

    #[test]
    fn test_gf2_128_reduction_constant() {
        // p(x) = x¹²⁸ + x⁷ + x² + x + 1, so x¹²⁸ ≡ R = x⁷+x²+x+1 = 0x87.
        assert_eq!(Gf2_128::new(1 << 127) * Gf2_128::new(2), Gf2_128::new(0x87));
        // x¹²⁹ = x·R = x⁸ + x³ + x² + x = 0x10e.
        assert_eq!(
            Gf2_128::new(1 << 127) * Gf2_128::new(4),
            Gf2_128::new(0x10e)
        );
    }

    #[test]
    fn test_gf2_128_inv_round_trip() {
        for raw in [
            1u128,
            2,
            3,
            0x87, // reduction constant R
            0xDEADBEEFCAFEBABE0123456789ABCDEF,
            1u128 << 127,                       // top bit
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, // all ones
            0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, // alternating
            0x7b5b54657374566563746f725d53475d, // Intel test vector operand
        ] {
            let x = Gf2_128::new(raw);
            let xi = x.inverse().unwrap();
            assert_eq!(x * xi, Gf2_128::one(), "x={raw:#034x}");
        }
        assert_eq!(Gf2_128::zero().inverse(), None);
    }

    #[test]
    fn test_gf2_128_mul() {
        for &(a, b, expected) in REFERENCE_PRODUCTS {
            let ours = (Gf2_128::new(a) * Gf2_128::new(b)).0;
            assert_eq!(
                ours, expected,
                "mismatch: a={a:#034x} b={b:#034x} ours={ours:#034x} expected={expected:#034x}"
            );
            // Commutativity spot-check on every vector.
            assert_eq!(
                Gf2_128::new(a) * Gf2_128::new(b),
                Gf2_128::new(b) * Gf2_128::new(a)
            );
        }
    }

    /// Reference products `(a, b, a·b)` in GF(2¹²⁸) under
    /// p(x) = x¹²⁸ + x⁷ + x² + x + 1. Values 0–10 are derived algebraically
    /// from the irreducible polynomial; the last entry is from Intel's
    /// Carry-Less Multiplication white paper.
    const REFERENCE_PRODUCTS: &[(u128, u128, u128)] = &[
        // identity / zero
        (0, 0, 0),
        (0, 0xDEADBEEFCAFEBABE0123456789ABCDEF, 0),
        (
            1,
            0xDEADBEEFCAFEBABE0123456789ABCDEF,
            0xDEADBEEFCAFEBABE0123456789ABCDEF,
        ),
        (
            0xDEADBEEFCAFEBABE0123456789ABCDEF,
            1,
            0xDEADBEEFCAFEBABE0123456789ABCDEF,
        ),
        // no-reduction cases
        (2, 2, 4),  // x · x = x²
        (3, 5, 15), // (1+x)(1+x²) = 1+x+x²+x³
        (3, 7, 9),  // (1+x)(1+x+x²) = 1 + x³
        // reduction-triggering cases (derived from x¹²⁸ ≡ x⁷+x²+x+1)
        (1 << 127, 2, 0x87),  // x¹²⁷ · x = x¹²⁸ ≡ R
        (1 << 127, 4, 0x10e), // x¹²⁷ · x² = x¹²⁹ = x·R = x⁸+x³+x²+x
        (0x87, 0x87, 0x4015), // R² = x¹⁴+x⁴+x²+1 (Freshman's dream)
        // x¹²⁷ · x¹²⁷ = x²⁵⁴ ≡ x¹²⁷+x¹²⁶+x¹²+x⁶+x⁵+x²+x+1
        (1 << 127, 1 << 127, 0xC0000000000000000000000000001067),
        // Intel® Carry-Less Multiplication Instruction white paper
        (
            0x7b5b54657374566563746f725d53475d,
            0x48692853686179295b477565726f6e5d,
            0x40229a09a5ed12e7e4e10da323506d2,
        ),
    ];
}
