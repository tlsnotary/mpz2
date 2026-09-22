//! WASM `simd128` backend for GF(2⁶⁴).
//!
//! Uses `bmul_simd::bmul64_full` (v128-parallelised BearSSL) for the
//! 64×64 carry-less product, then reduces mod p(x) = x⁶⁴+x⁴+x³+x+1
//! with the same shift/XOR chain as the soft backend. `inner_product`
//! keeps its accumulator in a v128 across the whole loop, amortising
//! both the reduction *and* the final bit-reverse+shift.

use std::arch::wasm32::*;

use crate::bmul_simd::{bit_spread_v128, bmul64_full, bmul64_lo_v128, rev64};

use super::Gf2_64;

#[inline]
pub(super) fn mul(a: u64, b: u64) -> u64 {
    let (lo, hi) = bmul64_full(a, b);
    reduce64(lo, hi)
}

/// Squaring via parallel bit-spread. In char 2,
/// `(Σ aᵢ xⁱ)² = Σ aᵢ x^(2i)`. Pack the low and high 32-bit halves of
/// `a` into the two v128 lanes and run the 32→64 bit-spread on both
/// simultaneously — no multiplies at all.
#[inline]
pub(super) fn square(a: u64) -> u64 {
    let v = bit_spread_v128(u64x2(a as u32 as u64, (a >> 32) as u64));
    let lo = u64x2_extract_lane::<0>(v);
    let hi = u64x2_extract_lane::<1>(v);
    reduce64(lo, hi)
}

#[inline]
pub(super) fn inner_product(a: &[Gf2_64], b: &[Gf2_64]) -> u64 {
    // Accumulate raw v128 partials (lane 0 = lo, lane 1 = bit-reversed hi-raw).
    // The lane 1 → hi conversion (rev64 + shift) is linear, so it commutes
    // with XOR accumulation and can be deferred to the end.
    let mut acc = u64x2_splat(0);
    for (x, y) in a.iter().zip(b.iter()) {
        let v = bmul64_lo_v128(u64x2(x.0, rev64(x.0)), u64x2(y.0, rev64(y.0)));
        acc = v128_xor(acc, v);
    }
    let lo = u64x2_extract_lane::<0>(acc);
    let hi = rev64(u64x2_extract_lane::<1>(acc)) >> 1;
    reduce64(lo, hi)
}

#[inline]
pub(super) fn inverse(a: u64) -> u64 {
    let mut y = square(a);
    let mut out = y;
    for _ in 2..64 {
        y = square(y);
        out = mul(out, y);
    }
    out
}

/// Reduce a 128-bit polynomial `hi·2⁶⁴ + lo` modulo
/// p(x) = x⁶⁴ + x⁴ + x³ + x + 1 (so `x⁶⁴ ≡ R = x⁴+x³+x+1`).
#[inline(always)]
fn reduce64(lo: u64, hi: u64) -> u64 {
    let folded_lo = hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
    let overflow = (hi >> 63) ^ (hi >> 61) ^ (hi >> 60);
    let overflow_folded = overflow ^ (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
    lo ^ folded_lo ^ overflow_folded
}
