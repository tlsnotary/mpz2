//! This crate provides types for working with finite fields.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![deny(unsafe_code)]

pub mod gf2;
pub mod gf2_128;
pub mod gf2_64;
pub mod p256;

#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "pclmulqdq"),
    all(target_arch = "wasm32", target_feature = "simd128"),
)))]
mod bmul;

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod bmul_simd;

// Shared by the soft backend and by the x86 Gf2_128 square path — the
// scalar bit-spread trick beats PCLMUL on dependent squarings.
#[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
mod spread;

use std::{
    error::Error,
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};

use hybrid_array::{Array, ArraySize};
use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use rand::{Rng, RngExt, distr::StandardUniform, prelude::Distribution};
use thiserror::Error;
use typenum::Unsigned;

/// A trait for finite fields.
pub trait Field:
    Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + Copy
    + Clone
    + Debug
    + 'static
    + Send
    + Sync
    + UniformRand
    + PartialOrd
    + Ord
    + PartialEq
    + Eq
    + FromBitIterator
    + GetBit<Lsb0>
    + GetBit<Msb0>
    + BitLength
    + Unpin
    + TryFrom<Array<u8, Self::ByteSize>, Error = FieldError>
{
    /// The number of bits of a field element.
    const BIT_SIZE: usize = <Self::BitSize as Unsigned>::USIZE;

    /// The number of bytes of a field element.
    const BYTE_SIZE: usize = <Self::ByteSize as Unsigned>::USIZE;

    /// The number of bits of a field element as a type number.
    type BitSize: ArraySize;

    /// The number of bytes of a field element as a type number.
    type ByteSize: ArraySize;

    /// Return the additive identity element.
    fn zero() -> Self;

    /// Return the multiplicative identity element.
    fn one() -> Self;

    /// Return a field element from a power of two.
    fn two_pow(rhs: u32) -> Self;

    /// Return the multiplicative inverse, returning `None` if the element is
    /// zero.
    fn inverse(self) -> Option<Self>;

    /// Return `self * self`.
    ///
    /// The default implementation is `self * self`. Concrete types may
    /// override this with a cheaper dedicated squaring routine — most
    /// notably, in characteristic-2 extension fields squaring is just a
    /// bit-spread of the coefficients and needs no carry-less multiply.
    #[inline]
    fn square(self) -> Self {
        self * self
    }

    /// Return field element as little-endian bytes.
    fn to_le_bytes(&self) -> Vec<u8>;

    /// Return field element as big-endian bytes.
    fn to_be_bytes(&self) -> Vec<u8>;

    /// Compute the inner product `Σ aᵢ · bᵢ` of two slices of field
    /// elements.
    ///
    /// When the `rayon` feature is enabled and the input is larger than
    /// ~L2 cache on a single core, the work is split across threads so
    /// each chunk stays cache-local on its worker core. Below that
    /// threshold the sequential chunk path runs directly — thread
    /// spawning overhead would dominate the gain.
    ///
    /// Concrete types override [`Self::inner_product_chunk`] (not this
    /// method) to provide an accelerated single-chunk implementation;
    /// the parallel path calls the override once per chunk and
    /// XOR/+-combines the partial results.
    ///
    /// # Panics
    ///
    /// Panics if the two slices have different lengths.
    #[inline]
    fn inner_product(a: &[Self], b: &[Self]) -> Self {
        assert_eq!(a.len(), b.len(), "inner_product: slice length mismatch");

        cfg_select! {
            feature = "rayon" => {
                // Target ~64 KB per chunk so each worker's chunk (plus
                // the matching chunk of `b`) fits comfortably in L1/L2.
                const TARGET_CHUNK_BYTES: usize = 64 * 1024;
                let chunk = (TARGET_CHUNK_BYTES / Self::BYTE_SIZE).max(1);
                // Only parallelise once we'd have ≥2 chunks' worth of
                // work — i.e. when a single core's cache wouldn't hold
                // both input slices anyway.
                if a.len() >= chunk * 2 {
                    use rayon::prelude::*;
                    a.par_chunks(chunk)
                        .zip(b.par_chunks(chunk))
                        .map(|(ac, bc)| Self::inner_product_chunk(ac, bc))
                        .reduce(Self::zero, |x, y| x + y)
                } else {
                    Self::inner_product_chunk(a, b)
                }
            }
            _ => Self::inner_product_chunk(a, b),
        }
    }

    /// Sequential inner-product kernel. Concrete types override this with
    /// their optimised single-threaded SIMD implementation;
    /// [`Self::inner_product`] calls it once (sequential) or once per chunk
    /// (parallel).
    #[doc(hidden)]
    #[inline]
    fn inner_product_chunk(a: &[Self], b: &[Self]) -> Self {
        a.iter()
            .zip(b.iter())
            .fold(Self::zero(), |acc, (x, y)| acc + *x * *y)
    }

    /// Compute the triple inner product `Σ aᵢ · bᵢ · cᵢ` of three slices
    /// of field elements.
    ///
    /// Same chunking/parallel dispatch as [`Self::inner_product`] — the
    /// kernel does a single reduction per chunk (vs. one per iteration
    /// for a naive fold through `Mul`), amortising reduction cost across
    /// the whole chunk.
    ///
    /// Concrete types override [`Self::double_inner_product_chunk`] (not
    /// this method) to provide an accelerated single-chunk
    /// implementation.
    ///
    /// # Panics
    ///
    /// Panics if the three slices do not all have the same length.
    #[inline]
    fn double_inner_product(a: &[Self], b: &[Self], c: &[Self]) -> Self {
        assert_eq!(
            a.len(),
            b.len(),
            "double_inner_product: slice length mismatch"
        );
        assert_eq!(
            a.len(),
            c.len(),
            "double_inner_product: slice length mismatch"
        );

        cfg_select! {
            feature = "rayon" => {
                const TARGET_CHUNK_BYTES: usize = 64 * 1024;
                let chunk = (TARGET_CHUNK_BYTES / Self::BYTE_SIZE).max(1);
                if a.len() >= chunk * 2 {
                    use rayon::prelude::*;
                    a.par_chunks(chunk)
                        .zip(b.par_chunks(chunk))
                        .zip(c.par_chunks(chunk))
                        .map(|((ac, bc), cc)| Self::double_inner_product_chunk(ac, bc, cc))
                        .reduce(Self::zero, |x, y| x + y)
                } else {
                    Self::double_inner_product_chunk(a, b, c)
                }
            }
            _ => Self::double_inner_product_chunk(a, b, c),
        }
    }

    /// Sequential triple-inner-product kernel. Concrete types override
    /// this with their optimised single-threaded implementation;
    /// [`Self::double_inner_product`] calls it once (sequential) or once
    /// per chunk (parallel).
    #[doc(hidden)]
    #[inline]
    fn double_inner_product_chunk(a: &[Self], b: &[Self], c: &[Self]) -> Self {
        a.iter()
            .zip(b.iter())
            .zip(c.iter())
            .fold(Self::zero(), |acc, ((x, y), z)| acc + *x * *y * *z)
    }
}

/// A field `Self` that is an extension of the base field `B`.
///
/// Implementors view `Self` as a `Self::BIT_SIZE / B::BIT_SIZE`-dimensional
/// vector space over `B`, with a fixed monomial basis available for
/// "pack `n` subfield values into one extension element" operations
/// (VOPE masks, random linear compressions of subfield tuples, …).
pub trait ExtensionField<B: Field>: Field {
    /// The monomial basis `[α^0, α^1, …, α^(d-1)]`, where `d` is the
    /// extension degree `Self::BIT_SIZE / B::BIT_SIZE`.
    ///
    /// The canonical subfield injection `B^d → Self` is
    /// [`Self::inner_product_subfield`] with `challenges = MONOMIAL_BASIS`.
    const MONOMIAL_BASIS: &'static [Self];

    /// Embed a base-field element into the extension field.
    fn embed(base: B) -> Self;

    /// `Σ values[i] · challenges[i]` with base-field values lifted
    /// into `Self` before multiplication. Use
    /// [`Self::MONOMIAL_BASIS`] as `challenges` for the canonical
    /// subfield injection, or a verifier-sampled slice for a random
    /// linear compression of a subfield tuple.
    ///
    /// The default uses `embed` + field multiplication. Concrete
    /// types can override for speed (e.g. `ExtensionField<Gf2>` can
    /// reduce each term to a conditional XOR).
    ///
    /// # Panics
    ///
    /// Panics if the two slices have different lengths.
    #[inline]
    fn inner_product_subfield(values: &[B], challenges: &[Self]) -> Self {
        assert_eq!(
            values.len(),
            challenges.len(),
            "inner_product_subfield: slice length mismatch",
        );
        values
            .iter()
            .zip(challenges.iter())
            .fold(Self::zero(), |acc, (v, c)| acc + Self::embed(*v) * *c)
    }
}

/// Error type for finite fields.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct FieldError(Box<dyn Error + Send + Sync + 'static>);

/// A trait for sampling random elements of the field.
///
/// This is helpful, because we do not need to import other traits since this is
/// a supertrait of field (which is not possible with `Standard` and
/// `Distribution`).
pub trait UniformRand: Sized {
    /// Return a random field element.
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self;
}

impl<T> UniformRand for T
where
    StandardUniform: Distribution<T>,
{
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        rng.sample(StandardUniform)
    }
}

/// Iteratively multiplies some field element with another field element.
///
/// This function multiplies the last element in `powers` with some other field
/// element `factor` and appends the result to `powers`. This process is
/// repeated `count` times.
///
/// * `powers` - The vector to which the new higher powers get pushed.
/// * `factor` - The field element with which the last element of the vector is
///   multiplied.
/// * `count` - How many products are computed.
pub fn compute_product_repeated<T: Field>(powers: &mut Vec<T>, factor: T, count: usize) {
    for _ in 0..count {
        let last_power = *powers
            .last()
            .expect("Vector is empty. Cannot compute higher powers");
        powers.push(factor * last_power);
    }
}

#[cfg(test)]
mod tests {
    use super::{Field, compute_product_repeated};
    use itybity::{GetBit, Lsb0, Msb0};
    use mpz_core::{Block, prg::Prg};
    use rand::SeedableRng;

    pub(crate) fn test_field_basic<T: Field>() {
        let mut rng = Prg::from_seed(Block::ZERO);
        let a = T::rand(&mut rng);

        let zero = T::zero();
        let one = T::one();

        assert_eq!(a + zero, a);
        assert_eq!(a * zero, zero);
        assert_eq!(a * one, a);
        assert_eq!(a * a.inverse().unwrap(), one);
        assert_eq!(one.inverse().unwrap(), one);
        assert_eq!(a + -a, zero);
    }

    pub(crate) fn test_field_compute_product_repeated<T: Field>() {
        let mut rng = Prg::from_seed(Block::ZERO);
        let a = T::rand(&mut rng);

        let mut powers = vec![a];
        let factor = a * a;

        compute_product_repeated(&mut powers, factor, 2);

        assert_eq!(powers[0], a);
        assert_eq!(powers[1], powers[0] * factor);
        assert_eq!(powers[2], powers[1] * factor);
    }

    pub(crate) fn test_field_square<T: Field>() {
        let mut rng = Prg::from_seed(Block::ZERO);
        // Zero and one.
        assert_eq!(T::zero().square(), T::zero());
        assert_eq!(T::one().square(), T::one());
        // Matches `x * x` for many random values.
        for _ in 0..1000 {
            let x = T::rand(&mut rng);
            assert_eq!(x.square(), x * x);
        }
    }

    pub(crate) fn test_field_axioms_random<T: Field>() {
        let mut rng = Prg::from_seed(Block::ZERO);
        let zero = T::zero();
        let one = T::one();

        for _ in 0..1000 {
            let a = T::rand(&mut rng);
            let b = T::rand(&mut rng);
            let c = T::rand(&mut rng);

            assert_eq!(a * b, b * a, "commutativity");
            assert_eq!((a * b) * c, a * (b * c), "associativity");
            assert_eq!(a * (b + c), a * b + a * c, "distributivity");
            assert_eq!(a + -a, zero, "additive inverse");
            #[allow(clippy::eq_op)]
            {
                assert_eq!(a - a, zero, "self-subtraction");
            }
            if a != zero {
                assert_eq!(a * a.inverse().unwrap(), one, "multiplicative inverse");
            }
        }
    }

    pub(crate) fn test_field_inner_product<T: Field>() {
        let mut rng = Prg::from_seed(Block::ZERO);

        // Empty → zero.
        assert_eq!(T::inner_product(&[], &[]), T::zero());

        // Length 1 → a · b.
        let a0 = T::rand(&mut rng);
        let b0 = T::rand(&mut rng);
        assert_eq!(T::inner_product(&[a0], &[b0]), a0 * b0);

        // Length 1024 — stresses the x86 accumulator across many folds.
        // Length 20_000 — crosses the `rayon` feature's parallel threshold
        // (~8192 for 16-byte types, higher for narrower), so it exercises
        // the par_chunks path when rayon is enabled and the sequential
        // path when it isn't. Either way the result must match the naive
        // fold bit-for-bit.
        for &len in &[17usize, 1024, 20_000] {
            let a: Vec<T> = (0..len).map(|_| T::rand(&mut rng)).collect();
            let b: Vec<T> = (0..len).map(|_| T::rand(&mut rng)).collect();

            let expected = a
                .iter()
                .zip(b.iter())
                .fold(T::zero(), |acc, (x, y)| acc + *x * *y);

            assert_eq!(T::inner_product(&a, &b), expected, "len={len}");
        }
    }

    pub(crate) fn test_field_double_inner_product<T: Field>() {
        let mut rng = Prg::from_seed(Block::ZERO);

        // Empty → zero.
        assert_eq!(T::double_inner_product(&[], &[], &[]), T::zero());

        // Length 1 → a · b · c.
        let a0 = T::rand(&mut rng);
        let b0 = T::rand(&mut rng);
        let c0 = T::rand(&mut rng);
        assert_eq!(T::double_inner_product(&[a0], &[b0], &[c0]), a0 * b0 * c0);

        for &len in &[17usize, 1024, 20_000] {
            let a: Vec<T> = (0..len).map(|_| T::rand(&mut rng)).collect();
            let b: Vec<T> = (0..len).map(|_| T::rand(&mut rng)).collect();
            let c: Vec<T> = (0..len).map(|_| T::rand(&mut rng)).collect();

            let expected = a
                .iter()
                .zip(b.iter())
                .zip(c.iter())
                .fold(T::zero(), |acc, ((x, y), z)| acc + *x * *y * *z);

            assert_eq!(T::double_inner_product(&a, &b, &c), expected, "len={len}");
        }
    }

    pub(crate) fn test_extension_field_subfield_inner_product<F, B>()
    where
        F: super::ExtensionField<B>,
        B: Field,
    {
        let mut rng = Prg::from_seed(Block::ZERO);

        // Empty → zero.
        assert_eq!(F::inner_product_subfield(&[], &[]), F::zero());

        // Across a range of lengths, the optimized impl must match the
        // semantics: embed each subfield value into `F`, then do a
        // regular extension-field inner product.
        for &len in &[1usize, 3, F::BIT_SIZE, 17, 1024] {
            let values: Vec<B> = (0..len).map(|_| B::rand(&mut rng)).collect();
            let challenges: Vec<F> = (0..len).map(|_| F::rand(&mut rng)).collect();

            let embedded: Vec<F> = values.iter().map(|v| F::embed(*v)).collect();
            let expected = F::inner_product(&embedded, &challenges);
            let got = F::inner_product_subfield(&values, &challenges);
            assert_eq!(got, expected, "len={len}");
        }

        // Sanity: injection via the monomial basis recovers the
        // subfield bits as the low-order coefficients of the result.
        // Well-defined whenever `B::BIT_SIZE * d == F::BIT_SIZE`.
        let one = B::one();
        let zero = B::zero();
        let d = F::MONOMIAL_BASIS.len();
        let mut values = vec![zero; d];
        values[0] = one;
        let r = F::inner_product_subfield(&values, F::MONOMIAL_BASIS);
        assert_eq!(r, F::embed(one), "monomial basis at index 0 == embed(one)");
    }

    pub(crate) fn test_field_bit_ops_lsb0<T: Field>() {
        let mut a = vec![false; T::BIT_SIZE];
        let mut b = vec![false; T::BIT_SIZE];

        a[0] = true;
        b[T::BIT_SIZE - 1] = true;

        let a = T::from_lsb0_iter(a);
        let b = T::from_lsb0_iter(b);

        assert_eq!(a, T::one());
        assert!(GetBit::<Lsb0>::get_bit(&a, 0));

        assert_eq!(b, T::two_pow(T::BIT_SIZE as u32 - 1));
        assert!(GetBit::<Lsb0>::get_bit(&b, T::BIT_SIZE - 1));
    }

    pub(crate) fn test_field_bit_ops_msb0<T: Field>() {
        let mut a = vec![false; T::BIT_SIZE];
        let mut b = vec![false; T::BIT_SIZE];

        a[T::BIT_SIZE - 1] = true;
        b[0] = true;

        let a = T::from_msb0_iter(a);
        let b = T::from_msb0_iter(b);

        assert_eq!(a, T::one());
        assert!(GetBit::<Msb0>::get_bit(&a, T::BIT_SIZE - 1));

        assert_eq!(b, T::two_pow(T::BIT_SIZE as u32 - 1));
        assert!(GetBit::<Msb0>::get_bit(&b, 0));
    }
}
