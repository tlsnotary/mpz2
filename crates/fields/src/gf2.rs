//! This module implements the binary field GF(2).

use std::ops::{Add, Mul, Neg, Sub};

use hybrid_array::{Array, typenum::U1};
use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use rand::{
    RngExt,
    distr::{Distribution, StandardUniform},
};
use serde::{Deserialize, Serialize};

use crate::{Field, FieldError};

/// An element of GF(2), i.e. a single bit under XOR/AND.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Gf2(pub bool);

impl Gf2 {
    /// The additive identity (zero).
    pub const ZERO: Self = Gf2(false);
    /// The multiplicative identity (one).
    pub const ONE: Self = Gf2(true);
}

impl Add for Gf2 {
    type Output = Self;
    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        Gf2(self.0 ^ rhs.0)
    }
}

impl Sub for Gf2 {
    type Output = Self;
    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        // Characteristic-2: subtraction equals addition.
        Gf2(self.0 ^ rhs.0)
    }
}

impl Mul for Gf2 {
    type Output = Self;
    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self {
        Gf2(self.0 & rhs.0)
    }
}

impl Neg for Gf2 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        // Characteristic-2: -x = x.
        self
    }
}

impl Distribution<Gf2> for StandardUniform {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Gf2 {
        Gf2(rng.random())
    }
}

impl BitLength for Gf2 {
    const BITS: usize = 1;
}

impl GetBit<Lsb0> for Gf2 {
    #[inline]
    fn get_bit(&self, index: usize) -> bool {
        index == 0 && self.0
    }
}

impl GetBit<Msb0> for Gf2 {
    #[inline]
    fn get_bit(&self, index: usize) -> bool {
        index == 0 && self.0
    }
}

impl FromBitIterator for Gf2 {
    #[inline]
    fn from_lsb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Gf2(iter.into_iter().next().unwrap_or(false))
    }
    #[inline]
    fn from_msb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Gf2(iter.into_iter().next().unwrap_or(false))
    }
}

impl TryFrom<Array<u8, U1>> for Gf2 {
    type Error = FieldError;
    fn try_from(value: Array<u8, U1>) -> Result<Self, Self::Error> {
        let [byte]: [u8; 1] = value.into();
        // Accept any byte; the low bit is the GF(2) element (matches
        // `Gf2_64`'s "any bytes interpret as the field element" convention).
        Ok(Gf2(byte & 1 != 0))
    }
}

impl Field for Gf2 {
    type BitSize = U1;
    type ByteSize = U1;

    fn zero() -> Self {
        Gf2::ZERO
    }
    fn one() -> Self {
        Gf2::ONE
    }
    fn two_pow(rhs: u32) -> Self {
        // In GF(2), 2 = 0, so 2^0 = 1 and 2^k = 0 for k ≥ 1.
        Gf2(rhs == 0)
    }
    fn inverse(self) -> Option<Self> {
        if self.0 { Some(self) } else { None }
    }
    fn to_le_bytes(&self) -> Vec<u8> {
        vec![u8::from(self.0)]
    }
    fn to_be_bytes(&self) -> Vec<u8> {
        vec![u8::from(self.0)]
    }
}

#[cfg(test)]
mod tests {
    use super::Gf2;
    use crate::{
        Field,
        tests::{test_field_bit_ops_lsb0, test_field_bit_ops_msb0},
    };

    #[test]
    fn gf2_arith() {
        let zero = Gf2::zero();
        let one = Gf2::one();
        assert_eq!(zero + zero, zero);
        assert_eq!(zero + one, one);
        assert_eq!(one + one, zero);
        assert_eq!(zero * one, zero);
        assert_eq!(one * one, one);
        assert_eq!(-one, one);
        assert_eq!(zero.inverse(), None);
        assert_eq!(one.inverse(), Some(one));
        assert_eq!(Gf2::two_pow(0), one);
        assert_eq!(Gf2::two_pow(1), zero);
    }

    #[test]
    fn gf2_bit_ops() {
        test_field_bit_ops_lsb0::<Gf2>();
        test_field_bit_ops_msb0::<Gf2>();
    }
}
