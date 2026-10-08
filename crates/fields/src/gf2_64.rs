//! This module implements the extension field GF(2^64).
//!
//! Uses the irreducible polynomial p(x) = x^64 + x^4 + x^3 + x + 1.

use std::ops::{Add, Mul, Neg, Sub};

use hybrid_array::{
    Array,
    typenum::{U8, U64},
};
use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use rand::distr::{Distribution, StandardUniform};
use serde::{Deserialize, Serialize};

use crate::{ExtensionField, Field, FieldError, gf2::Gf2};

/// An element of GF(2^64), represented as a `u64`.
///
/// Field arithmetic uses the irreducible polynomial
/// p(x) = x^64 + x^4 + x^3 + x + 1.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Gf2_64(pub u64);

impl Gf2_64 {
    /// The additive identity (zero).
    pub const ZERO: Self = Gf2_64(0);
    /// The multiplicative identity (one).
    pub const ONE: Self = Gf2_64(1);
}

impl Add for Gf2_64 {
    type Output = Self;
    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        Gf2_64(self.0 ^ rhs.0)
    }
}

impl Sub for Gf2_64 {
    type Output = Self;
    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        // Characteristic-2: subtraction equals addition.
        Gf2_64(self.0 ^ rhs.0)
    }
}

impl Mul for Gf2_64 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Gf2_64(gf64_mul(self.0, rhs.0))
    }
}

impl Neg for Gf2_64 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        // Characteristic-2: -x = x.
        self
    }
}

impl Distribution<Gf2_64> for StandardUniform {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Gf2_64 {
        Gf2_64(self.sample(rng))
    }
}

impl TryFrom<Array<u8, U8>> for Gf2_64 {
    type Error = FieldError;

    fn try_from(value: Array<u8, U8>) -> Result<Self, Self::Error> {
        let inner: [u8; 8] = value.into();
        Ok(Gf2_64(u64::from_be_bytes(inner)))
    }
}

impl BitLength for Gf2_64 {
    const BITS: usize = 64;
}

impl GetBit<Lsb0> for Gf2_64 {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Lsb0>::get_bit(&self.0, index)
    }
}

impl GetBit<Msb0> for Gf2_64 {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Msb0>::get_bit(&self.0, index)
    }
}

impl FromBitIterator for Gf2_64 {
    fn from_lsb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Gf2_64(u64::from_lsb0_iter(iter))
    }

    fn from_msb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Gf2_64(u64::from_msb0_iter(iter))
    }
}

impl Field for Gf2_64 {
    type BitSize = U64;
    type ByteSize = U8;

    fn zero() -> Self {
        Gf2_64::ZERO
    }

    fn one() -> Self {
        Gf2_64::ONE
    }

    fn two_pow(rhs: u32) -> Self {
        Gf2_64(1u64 << rhs)
    }

    fn inverse(self) -> Option<Self> {
        if self == Gf2_64::ZERO {
            return None;
        }
        Some(Gf2_64(gf64_inverse(self.0)))
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }

    #[inline]
    fn inner_product_chunk(a: &[Self], b: &[Self]) -> Self {
        Gf2_64(gf64_inner_product(a, b))
    }

    #[inline]
    fn double_inner_product_chunk(a: &[Self], b: &[Self], c: &[Self]) -> Self {
        Gf2_64(gf64_double_inner_product(a, b, c))
    }

    #[inline]
    fn square(self) -> Self {
        Gf2_64(gf64_square(self.0))
    }
}

/// Monomial basis `[α^0, α^1, …, α^63]` of `GF(2^64)` over `GF(2)`.
static MONOMIAL_BASIS_GF2_64: [Gf2_64; 64] = {
    let mut out = [Gf2_64(0); 64];
    let mut i = 0;
    while i < 64 {
        out[i] = Gf2_64(1u64 << i);
        i += 1;
    }
    out
};

impl ExtensionField<Gf2> for Gf2_64 {
    const MONOMIAL_BASIS: &'static [Self] = &MONOMIAL_BASIS_GF2_64;

    #[inline]
    fn embed(base: Gf2) -> Self {
        Gf2_64(u64::from(base.0))
    }

    /// Constant-time masked XOR — no field multiplications and no
    /// data-dependent branches.
    #[inline]
    fn inner_product_subfield(values: &[Gf2], challenges: &[Self]) -> Self {
        assert_eq!(
            values.len(),
            challenges.len(),
            "inner_product_subfield: slice length mismatch",
        );
        let mut acc = 0u64;
        for (v, c) in values.iter().zip(challenges.iter()) {
            let mask = (v.0 as u64).wrapping_neg();
            acc ^= c.0 & mask;
        }
        Gf2_64(acc)
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
fn gf64_mul(a: u64, b: u64) -> u64 {
    backend::mul(a, b)
}

#[inline(always)]
fn gf64_inner_product(a: &[Gf2_64], b: &[Gf2_64]) -> u64 {
    backend::inner_product(a, b)
}

#[inline(always)]
fn gf64_double_inner_product(a: &[Gf2_64], b: &[Gf2_64], c: &[Gf2_64]) -> u64 {
    backend::double_inner_product(a, b, c)
}

#[inline(always)]
fn gf64_inverse(a: u64) -> u64 {
    backend::inverse(a)
}

#[inline(always)]
fn gf64_square(a: u64) -> u64 {
    backend::square(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{
        test_extension_field_subfield_inner_product, test_field_axioms_random,
        test_field_double_inner_product, test_field_inner_product, test_field_square,
    };

    #[test]
    fn test_inner_product() {
        test_field_inner_product::<Gf2_64>();
    }

    #[test]
    fn test_double_inner_product() {
        test_field_double_inner_product::<Gf2_64>();
    }

    #[test]
    fn test_subfield_inner_product() {
        test_extension_field_subfield_inner_product::<Gf2_64, Gf2>();
    }

    #[test]
    fn test_axioms_random() {
        test_field_axioms_random::<Gf2_64>();
    }

    #[test]
    fn test_square() {
        test_field_square::<Gf2_64>();
    }

    #[test]
    #[should_panic(expected = "inner_product: slice length mismatch")]
    fn test_inner_product_length_mismatch() {
        let a = [Gf2_64::ONE, Gf2_64::ONE];
        let b = [Gf2_64::ONE];
        let _ = Gf2_64::inner_product(&a, &b);
    }

    #[test]
    fn test_reduction_constant() {
        // p(x) = x⁶⁴ + x⁴ + x³ + x + 1, so x⁶⁴ ≡ R = x⁴ + x³ + x + 1 = 0x1b.
        // x⁶³ · x = x⁶⁴ ≡ R.
        assert_eq!(Gf2_64(1 << 63) * Gf2_64(2), Gf2_64(0x1b));
        // x⁶³ · x² = x⁶⁵ = x·R = x⁵ + x⁴ + x² + x = 0x36.
        assert_eq!(Gf2_64(1 << 63) * Gf2_64(4), Gf2_64(0x36));
    }

    #[test]
    fn test_basic_arithmetic() {
        let zero = Gf2_64::ZERO;
        let one = Gf2_64::ONE;

        assert_eq!(one * one, one);
        assert_eq!(one * zero, zero);
        assert_eq!(zero * one, zero);
        assert_eq!(one + one, zero);
        assert_eq!(one + zero, one);
    }

    #[test]
    fn test_associativity() {
        let a = Gf2_64(0x123456789ABCDEF0);
        let b = Gf2_64(0xFEDCBA9876543210);
        let c = Gf2_64(0xDEADBEEFCAFEBABE);

        let ab_c = (a * b) * c;
        let a_bc = a * (b * c);
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn test_commutativity() {
        let a = Gf2_64(0xAAAABBBBCCCCDDDD);
        let b = Gf2_64(0x1111222233334444);

        assert_eq!(a * b, b * a);
    }

    #[test]
    fn test_distributivity() {
        let a = Gf2_64(0x123456789ABCDEF0);
        let b = Gf2_64(0xFEDCBA9876543210);
        let c = Gf2_64(0xDEADBEEFCAFEBABE);

        // a * (b + c) = a*b + a*c
        let lhs = a * (b + c);
        let rhs = a * b + a * c;
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_inv_round_trip() {
        // For a handful of nonzero elements, x · inv(x) = 1.
        for raw in [
            1u64,
            2,
            3,
            0x1234_5678,
            0xDEAD_BEEF_CAFE_BABE,
            0xFFFF_FFFF_FFFF_FFFF,
        ] {
            let x = Gf2_64(raw);
            let xi = x.inverse().unwrap();
            assert_eq!(x * xi, Gf2_64::ONE, "x={raw:#x}");
        }
    }

    #[test]
    fn test_mul_edge_cases() {
        for &(a, b, expected) in REFERENCE_PRODUCTS {
            let ours = (Gf2_64(a) * Gf2_64(b)).0;
            assert_eq!(
                ours, expected,
                "mismatch: a={a:#018x} b={b:#018x} ours={ours:#018x} expected={expected:#018x}"
            );
        }
    }

    /// Reference products `(a, b, a·b)` in GF(2⁶⁴), computed in SageMath
    /// against p(x) = x⁶⁴ + x⁴ + x³ + x + 1.
    const REFERENCE_PRODUCTS: &[(u64, u64, u64)] = &[
        (0xDEADBEEFCAFEBABE, 0x0000000000000001, 0xDEADBEEFCAFEBABE), // identity-right
        (0x0000000000000001, 0xDEADBEEFCAFEBABE, 0xDEADBEEFCAFEBABE), // identity-left
        (0xDEADBEEFCAFEBABE, 0x0000000000000000, 0x0000000000000000), // zero-right
        (0x0000000000000000, 0xDEADBEEFCAFEBABE, 0x0000000000000000), // zero-left
        (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x5555555555555513), // all-ones-squared
        (0x8000000000000000, 0x8000000000000000, 0xC00000000000005A), // top-bit-squared
        (0x0000000100000000, 0x0000000100000000, 0x000000000000001B), // bit32-squared
        (0x0000000000000010, 0x1000000000000000, 0x000000000000001B), // bit4-x-bit60
        (0x0000000000000008, 0x2000000000000000, 0x000000000000001B), // bit3-x-bit61
        (0x000000000000001B, 0x000000000000001B, 0x0000000000000145), // reduction-const-squared
        (0xAAAAAAAAAAAAAAAA, 0xAAAAAAAAAAAAAAAA, 0xEEEEEEEEEEEEEEB2), // alternating-squared
        (0x0000000000000001, 0x0000000000000001, 0x0000000000000001), // one-squared
        (0x8000000000000000, 0x0000000000000001, 0x8000000000000000), // bit63-times-one
        (0xDEADBEEFCAFEBABE, 0xDEADBEEFCAFEBABE, 0x3C5EFE39F55F5E12), // x-times-x
        (0x0123456789ABCDEF, 0xFEDCBA9876543210, 0x48827AB55D976FA0),
        (0xA5A5A5A5A5A5A5A5, 0x5A5A5A5A5A5A5A5A, 0x0257025702570279),
        (0x1111222233334444, 0x5555666677778888, 0x6E6EC6C6FCFD2524),
        (0x8000000000000001, 0x8000000000000001, 0xC00000000000005B),
        (0xCAFEBABEDEADBEEF, 0x0123456789ABCDEF, 0x63DB23766D1CD7C9),
        (0xFFFF0000FFFF0000, 0x0000FFFF0000FFFF, 0x0007555555520000),
    ];
}
