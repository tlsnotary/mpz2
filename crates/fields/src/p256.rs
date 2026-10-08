//! This module implements the prime field of P256.

use std::ops::{Add, Mul, Neg, Sub};

use crypto_bigint::{
    ArrayEncoding, NonZero, RandomMod, U256, const_monty_params,
    modular::{ConstMontyForm, ConstMontyParams},
};
use hybrid_array::Array;
use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use rand::{distr::StandardUniform, prelude::Distribution};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use typenum::{U32, U256 as TU256};

use crate::{Field, FieldError};

const_monty_params!(
    P256Modulus,
    U256,
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "The P-256 base field modulus p = 2^256 - 2^224 + 2^192 + 2^96 - 1."
);

type Fq = ConstMontyForm<P256Modulus, { U256::LIMBS }>;

const MODULUS_NZ: &NonZero<U256> = P256Modulus::PARAMS.modulus().as_nz_ref();

/// A type for holding field elements of P256.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "[u8; 32]")]
#[serde(try_from = "[u8; 32]")]
pub struct P256(Fq);

opaque_debug::implement!(P256);

impl P256 {
    fn canonical(&self) -> U256 {
        self.0.retrieve()
    }
}

impl PartialOrd for P256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for P256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_montgomery().cmp(other.0.as_montgomery())
    }
}

impl From<P256> for [u8; 32] {
    fn from(value: P256) -> Self {
        value.canonical().to_le_byte_array().into()
    }
}

impl TryFrom<[u8; 32]> for P256 {
    type Error = FieldError;

    /// Converts little-endian bytes into a P256 field element.
    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        let int = U256::from_le_slice(&value);
        if int >= *P256Modulus::PARAMS.modulus().as_ref() {
            return Err(FieldError(Box::new(P256Error(ErrorRepr::NotCanonical))));
        }
        Ok(P256(Fq::new(&int)))
    }
}

impl TryFrom<Array<u8, U32>> for P256 {
    type Error = FieldError;

    fn try_from(value: Array<u8, U32>) -> Result<Self, Self::Error> {
        let inner: [u8; 32] = value.into();
        P256::try_from(inner)
    }
}

impl Distribution<P256> for StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> P256 {
        P256(Fq::new(&U256::random_mod_vartime(rng, MODULUS_NZ)))
    }
}

impl Add for P256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sub for P256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Mul for P256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Neg for P256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Field for P256 {
    type BitSize = TU256;

    type ByteSize = U32;

    fn zero() -> Self {
        P256(Fq::ZERO)
    }

    fn one() -> Self {
        P256(Fq::ONE)
    }

    fn two_pow(rhs: u32) -> Self {
        let mut out = Fq::ONE;
        for _ in 0..rhs {
            out = out.double();
        }
        P256(out)
    }

    fn inverse(self) -> Option<Self> {
        self.0.invert().into_option().map(P256)
    }

    fn square(self) -> Self {
        P256(self.0.square())
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        self.canonical().to_le_bytes().as_ref().to_vec()
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        self.canonical().to_be_bytes().as_ref().to_vec()
    }
}

impl BitLength for P256 {
    const BITS: usize = 256;
}

impl GetBit<Lsb0> for P256 {
    fn get_bit(&self, index: usize) -> bool {
        self.canonical().bit_vartime(index as u32)
    }
}

impl GetBit<Msb0> for P256 {
    fn get_bit(&self, index: usize) -> bool {
        self.canonical().bit_vartime((255 - index) as u32)
    }
}

impl FromBitIterator for P256 {
    fn from_lsb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        let bytes = <[u8; 32]>::from_lsb0_iter(iter);
        P256(Fq::new(&U256::from_le_slice(&bytes)))
    }

    fn from_msb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        let bytes = <[u8; 32]>::from_msb0_iter(iter);
        P256(Fq::new(&U256::from_be_slice(&bytes)))
    }
}

/// Errors arising from constructing a P-256 field element from bytes.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct P256Error(ErrorRepr);

#[derive(Debug, Error)]
enum ErrorRepr {
    #[error("byte encoding is not a canonical field element (value ≥ modulus)")]
    NotCanonical,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_core::{Block, prg::Prg};
    use rand::{RngExt, SeedableRng};

    use crate::tests::{
        test_field_basic, test_field_bit_ops_lsb0, test_field_bit_ops_msb0,
        test_field_compute_product_repeated,
    };

    #[test]
    fn test_p256_basic() {
        test_field_basic::<P256>();
    }

    #[test]
    fn test_p256_compute_product_repeated() {
        test_field_compute_product_repeated::<P256>();
    }

    #[test]
    fn test_p256_bit_ops() {
        test_field_bit_ops_lsb0::<P256>();
        test_field_bit_ops_msb0::<P256>();
    }

    #[test]
    fn test_p256_serialize() {
        let mut rng = Prg::from_seed(Block::ZERO);

        for _ in 0..32 {
            let a: P256 = rng.random();
            let bytes: [u8; 32] = a.into();
            let b = P256::try_from(bytes).unwrap();

            assert_eq!(a, b);
        }
    }
}
