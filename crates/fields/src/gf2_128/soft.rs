//! Portable software backend for GF(2¹²⁸) — uses BearSSL-style
//! constant-time `bmul128_full` (four `bmul64_full` calls) to avoid
//! schoolbook's per-bit u128 loop, and amortises reduction across the
//! inner-product accumulator.

use crate::{bmul::bmul128_full, spread::bit_spread_u32};

use super::Gf2_128;

#[inline]
pub(super) fn mul(a: u128, b: u128) -> u128 {
    let (lo, hi) = bmul128_full(a, b);
    reduce128(lo, hi)
}

/// Squaring via bit-spread. In characteristic 2, `(a_lo + a_hi·x⁶⁴)² =
/// a_lo² + a_hi²·x¹²⁸` — the cross term vanishes — and each half-square
/// is a pure bit-spread of the input's bits to double their positions.
/// Four 32→64 bit-spreads form the full 256-bit squared polynomial.
#[inline]
pub(super) fn square(a: u128) -> u128 {
    let a_ll = bit_spread_u32(a as u32); // a_lo low 32 → bits [0..64]
    let a_lh = bit_spread_u32((a >> 32) as u32); // a_lo high 32 → bits [64..128]
    let a_hl = bit_spread_u32((a >> 64) as u32); // a_hi low 32 → bits [128..192]
    let a_hh = bit_spread_u32((a >> 96) as u32); // a_hi high 32 → bits [192..256]

    let lo = ((a_lh as u128) << 64) | (a_ll as u128);
    let hi = ((a_hh as u128) << 64) | (a_hl as u128);
    reduce128(lo, hi)
}

/// Multiplicative inverse via Fermat's little theorem. Uses the cheaper
/// `square` for the ~half of the chain that's squarings.
#[inline]
pub(super) fn inverse(a: u128) -> u128 {
    let mut y = square(a);
    let mut out = y;
    for _ in 2..128 {
        y = square(y);
        out = mul(out, y);
    }
    out
}

#[inline]
pub(super) fn inner_product(a: &[Gf2_128], b: &[Gf2_128]) -> u128 {
    let mut acc_lo = 0u128;
    let mut acc_hi = 0u128;
    for (x, y) in a.iter().zip(b.iter()) {
        let (lo, hi) = bmul128_full(x.0, y.0);
        acc_lo ^= lo;
        acc_hi ^= hi;
    }
    reduce128(acc_lo, acc_hi)
}

/// `Σ aᵢ · bᵢ · cᵢ`. One reduction per iteration for the `aᵢ·bᵢ`
/// intermediate, one post-loop reduction on the accumulated
/// `(aᵢbᵢ)·cᵢ` carry-less products.
#[inline]
pub(super) fn double_inner_product(a: &[Gf2_128], b: &[Gf2_128], c: &[Gf2_128]) -> u128 {
    let mut acc_lo = 0u128;
    let mut acc_hi = 0u128;
    for ((x, y), z) in a.iter().zip(b.iter()).zip(c.iter()) {
        let (xy_lo, xy_hi) = bmul128_full(x.0, y.0);
        let xy = reduce128(xy_lo, xy_hi);
        let (p_lo, p_hi) = bmul128_full(xy, z.0);
        acc_lo ^= p_lo;
        acc_hi ^= p_hi;
    }
    reduce128(acc_lo, acc_hi)
}

/// Reduce a 256-bit polynomial `hi·2¹²⁸ + lo` modulo
/// p(x) = x¹²⁸ + x⁷ + x² + x + 1 (so `x¹²⁸ ≡ R = x⁷ + x² + x + 1`).
///
/// First round folds `hi · R` (≤ 135 bits) back; overflow from the shifts
/// is at most 7 bits and is folded once more (its `· R` fits in 14 bits).
#[inline(always)]
fn reduce128(lo: u128, hi: u128) -> u128 {
    // Low 128 bits of `hi · R`: u128 shifts silently drop the top bits.
    let folded_lo = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    // Bits shifted past position 128 — at most 7 bits, at positions [0..7].
    //   from <<1: bit 127 of hi → overflow bit 0
    //   from <<2: bits 126..127 → overflow bits 0..1
    //   from <<7: bits 121..127 → overflow bits 0..6
    let overflow = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
    // `overflow · R` has ≤ 14 bits; no further reduction needed.
    let overflow_folded = overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);
    lo ^ folded_lo ^ overflow_folded
}
