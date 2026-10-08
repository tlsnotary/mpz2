//! x86_64 PCLMULQDQ fast path for GF(2¹²⁸). Multiply and inner-product
//! share carry-less multiply (`clmul128`) and reduction (`reduce128`).
#![allow(unsafe_code)]

use std::arch::x86_64::*;

use crate::spread::bit_spread_u32;

use super::Gf2_128;

#[inline(always)]
pub(super) fn mul(a: u128, b: u128) -> u128 {
    // SAFETY: gated on `target_feature = "pclmulqdq"`, SSE2 + PCLMULQDQ
    // are guaranteed available.
    unsafe {
        let a_vec = load(a);
        let b_vec = load(b);
        let (lo, hi) = clmul128(a_vec, b_vec);
        extract(reduce128(lo, hi))
    }
}

/// Squaring via scalar bit-spread — **faster than CLMUL** on x86 for
/// isolated squarings. In char 2, squaring is just "spread each bit to
/// twice its index", with all cross terms vanishing. Four 32→64 spreads
/// form the 256-bit squared polynomial; each spread is five rounds of
/// single-cycle shift/mask ops with excellent ILP, whereas a CLMUL
/// square would chain four dependent 7-cycle CLMULs (2 for the square
/// itself, 2 more for the modular reduction).
///
/// Measured: this is ~2× faster than the `sq128`/CLMUL-reduce path on
/// Skylake-class cores. See `square_xmm` below for the CLMUL variant
/// that stays register-resident inside the `inverse` loop.
#[inline(always)]
pub(super) fn square(a: u128) -> u128 {
    let a_ll = bit_spread_u32(a as u32); // a_lo low 32  → bits [0..64]
    let a_lh = bit_spread_u32((a >> 32) as u32); // a_lo high 32 → bits [64..128]
    let a_hl = bit_spread_u32((a >> 64) as u32); // a_hi low 32  → bits [128..192]
    let a_hh = bit_spread_u32((a >> 96) as u32); // a_hi high 32 → bits [192..256]

    let lo = ((a_lh as u128) << 64) | (a_ll as u128);
    let hi = ((a_hh as u128) << 64) | (a_hl as u128);
    reduce128_scalar(lo, hi)
}

/// Scalar reduction of a 256-bit polynomial modulo
/// p(x) = x¹²⁸ + x⁷ + x² + x + 1. Used by the bit-spread `square`
/// path above; the XMM-resident `reduce128` intrinsic variant below is
/// used by everything that's already in XMM (mul, inner_product,
/// square_xmm inside inverse).
#[inline(always)]
fn reduce128_scalar(lo: u128, hi: u128) -> u128 {
    let folded_lo = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    let overflow = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
    let overflow_folded = overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);
    lo ^ folded_lo ^ overflow_folded
}

/// Multiplicative inverse via Fermat's little theorem — keeps the running
/// state in XMM across all 127 squarings + 126 accumulating multiplies,
/// collapsing 254 GPR↔XMM transfers down to 2. Uses the 2-CLMUL
/// squaring path on the squaring half of the chain.
#[inline(always)]
pub(super) fn inverse(a: u128) -> u128 {
    // SAFETY: see `mul`.
    unsafe {
        let x = load(a);
        // Fermat: x⁻¹ = x^(2¹²⁸ − 2) = x² · x⁴ · x⁸ · … · x^(2¹²⁷).
        let mut y = square_xmm(x); // x²
        let mut out = y;
        for _ in 2..128 {
            y = square_xmm(y); // y ← y² (2 CLMULs)
            out = mul_xmm(out, y); // out ← out · y (4 CLMULs)
        }
        extract(out)
    }
}

#[inline(always)]
unsafe fn mul_xmm(a: __m128i, b: __m128i) -> __m128i {
    unsafe {
        let (lo, hi) = clmul128(a, b);
        reduce128(lo, hi)
    }
}

#[inline(always)]
unsafe fn square_xmm(a: __m128i) -> __m128i {
    unsafe {
        let (lo, hi) = sq128(a);
        reduce128(lo, hi)
    }
}

#[inline(always)]
pub(super) fn inner_product(a: &[Gf2_128], b: &[Gf2_128]) -> u128 {
    // SAFETY: see `mul`.
    unsafe {
        let mut acc_lo = _mm_setzero_si128();
        let mut acc_hi = _mm_setzero_si128();

        // Accumulate 256-bit carry-less products; reduce once at the end.
        for (x, y) in a.iter().zip(b.iter()) {
            let (lo, hi) = clmul128(load(x.0), load(y.0));
            acc_lo = _mm_xor_si128(acc_lo, lo);
            acc_hi = _mm_xor_si128(acc_hi, hi);
        }

        extract(reduce128(acc_lo, acc_hi))
    }
}

/// `Σ aᵢ · bᵢ · cᵢ`. One reduction per iteration for the `aᵢ·bᵢ`
/// intermediate (needed as a 128-bit operand for the second CLMUL), then
/// a single post-loop reduction on the accumulated `(aᵢbᵢ)·cᵢ` carry-less
/// products — vs. the naive fold which pays two reductions per iteration.
#[inline(always)]
pub(super) fn double_inner_product(a: &[Gf2_128], b: &[Gf2_128], c: &[Gf2_128]) -> u128 {
    // SAFETY: see `mul`.
    unsafe {
        let mut acc_lo = _mm_setzero_si128();
        let mut acc_hi = _mm_setzero_si128();

        for ((x, y), z) in a.iter().zip(b.iter()).zip(c.iter()) {
            let (xy_lo, xy_hi) = clmul128(load(x.0), load(y.0));
            let xy = reduce128(xy_lo, xy_hi);
            let (p_lo, p_hi) = clmul128(xy, load(z.0));
            acc_lo = _mm_xor_si128(acc_lo, p_lo);
            acc_hi = _mm_xor_si128(acc_hi, p_hi);
        }

        extract(reduce128(acc_lo, acc_hi))
    }
}

/// 256-bit carry-less square of a 128-bit input (two 64×64 CLMULs). In
/// characteristic 2, all cross terms vanish — we only need `a_lo²`
/// (for bits [0..128]) and `a_hi²` (for bits [128..256]).
#[inline(always)]
unsafe fn sq128(a: __m128i) -> (__m128i, __m128i) {
    unsafe {
        let lo = _mm_clmulepi64_si128(a, a, 0x00); // a_lo · a_lo
        let hi = _mm_clmulepi64_si128(a, a, 0x11); // a_hi · a_hi
        (lo, hi)
    }
}

/// 256-bit carry-less product of two 128-bit inputs (four 64×64 CLMULs).
///
/// Returns `(lo, hi)` such that the 256-bit product is `hi·x^128 + lo`.
#[inline(always)]
unsafe fn clmul128(a: __m128i, b: __m128i) -> (__m128i, __m128i) {
    unsafe {
        //   t00 = a_lo · b_lo  → bits [0..128]
        //   t11 = a_hi · b_hi  → bits [128..256]
        //   t01 = a_hi · b_lo  → bits  [64..192]
        //   t10 = a_lo · b_hi  → bits  [64..192]
        let t00 = _mm_clmulepi64_si128(a, b, 0x00);
        let t11 = _mm_clmulepi64_si128(a, b, 0x11);
        let t01 = _mm_clmulepi64_si128(a, b, 0x01);
        let t10 = _mm_clmulepi64_si128(a, b, 0x10);

        let mid = _mm_xor_si128(t01, t10);
        let lo = _mm_xor_si128(t00, _mm_slli_si128(mid, 8));
        let hi = _mm_xor_si128(t11, _mm_srli_si128(mid, 8));
        (lo, hi)
    }
}

/// Reduce a 256-bit polynomial `hi·x^128 + lo` modulo p(x) = x^128 + x^7 +
/// x^2 + x + 1. Since x^128 ≡ R = x^7 + x^2 + x + 1 (mod p), the result
/// is `lo + hi · R (mod p)`, computed in two CLMUL rounds.
#[inline(always)]
unsafe fn reduce128(lo: __m128i, hi: __m128i) -> __m128i {
    unsafe {
        let poly = _mm_set_epi64x(0, 0x87);

        // Round 1: hi · R — at most 135 bits.
        let t_lo = _mm_clmulepi64_si128(hi, poly, 0x00);
        let t_hi = _mm_clmulepi64_si128(hi, poly, 0x01);
        let folded_lo = _mm_xor_si128(t_lo, _mm_slli_si128(t_hi, 8));
        let overflow = _mm_srli_si128(t_hi, 8); // ≤ 7 bits at [128..135]
        let r1 = _mm_xor_si128(lo, folded_lo);

        // Round 2: overflow · R — at most 14 bits, no further reduction.
        let t2 = _mm_clmulepi64_si128(overflow, poly, 0x00);
        _mm_xor_si128(r1, t2)
    }
}

#[inline(always)]
unsafe fn load(x: u128) -> __m128i {
    unsafe { _mm_set_epi64x((x >> 64) as i64, x as i64) }
}

#[inline(always)]
unsafe fn extract(x: __m128i) -> u128 {
    unsafe {
        let lo = _mm_cvtsi128_si64(x) as u64 as u128;
        let hi = _mm_extract_epi64(x, 1) as u64 as u128;
        (hi << 64) | lo
    }
}
