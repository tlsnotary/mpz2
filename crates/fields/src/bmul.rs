//! Portable carry-less multiplication primitives.
//!
//! Implements a constant-time 64×64 → 128 bit carry-less ("bmul") multiply
//! using the BearSSL bit-interleaving trick (sparse 1-in-4 bit masks that
//! prevent integer-multiplication carries from spilling into neighbouring
//! "slots"). The high half of the product is recovered via the
//! reverse-multiply identity `hi(x·y) = rev₆₄(lo(rev(x)·rev(y))) >> 1`.
//!
//! Adapted from BearSSL's `ghash_ctmul64` (MIT licensed, © 2016 Thomas Pornin).

/// Returns the low 64 bits of the carry-less product `x · y`.
#[inline(always)]
fn bmul64_lo(x: u64, y: u64) -> u64 {
    let a0 = x & 0x1111_1111_1111_1111;
    let a1 = x & 0x2222_2222_2222_2222;
    let a2 = x & 0x4444_4444_4444_4444;
    let a3 = x & 0x8888_8888_8888_8888;
    let b0 = y & 0x1111_1111_1111_1111;
    let b1 = y & 0x2222_2222_2222_2222;
    let b2 = y & 0x4444_4444_4444_4444;
    let b3 = y & 0x8888_8888_8888_8888;

    let mut z0 =
        a0.wrapping_mul(b0) ^ a1.wrapping_mul(b3) ^ a2.wrapping_mul(b2) ^ a3.wrapping_mul(b1);
    let mut z1 =
        a0.wrapping_mul(b1) ^ a1.wrapping_mul(b0) ^ a2.wrapping_mul(b3) ^ a3.wrapping_mul(b2);
    let mut z2 =
        a0.wrapping_mul(b2) ^ a1.wrapping_mul(b1) ^ a2.wrapping_mul(b0) ^ a3.wrapping_mul(b3);
    let mut z3 =
        a0.wrapping_mul(b3) ^ a1.wrapping_mul(b2) ^ a2.wrapping_mul(b1) ^ a3.wrapping_mul(b0);

    z0 &= 0x1111_1111_1111_1111;
    z1 &= 0x2222_2222_2222_2222;
    z2 &= 0x4444_4444_4444_4444;
    z3 &= 0x8888_8888_8888_8888;

    z0 | z1 | z2 | z3
}

/// Bit-reverses a `u64` in constant time.
#[inline(always)]
fn rev64(mut x: u64) -> u64 {
    x = ((x & 0x5555_5555_5555_5555) << 1) | ((x >> 1) & 0x5555_5555_5555_5555);
    x = ((x & 0x3333_3333_3333_3333) << 2) | ((x >> 2) & 0x3333_3333_3333_3333);
    x = ((x & 0x0f0f_0f0f_0f0f_0f0f) << 4) | ((x >> 4) & 0x0f0f_0f0f_0f0f_0f0f);
    x.swap_bytes()
}

/// Full 64×64 → 128 bit carry-less product of `x` and `y`.
///
/// Returns `(lo, hi)` such that the 128-bit product is `hi·2⁶⁴ + lo`.
#[inline(always)]
pub(crate) fn bmul64_full(x: u64, y: u64) -> (u64, u64) {
    let lo = bmul64_lo(x, y);
    // For 64-bit polynomials x, y, `rev128(x·y) = rev(x)·rev(y) >> 1`
    // (the product has degree ≤ 126, i.e. bit 127 is always zero). So
    // `hi64(x·y) = rev64(lo64(rev(x)·rev(y))) >> 1`.
    let hi = rev64(bmul64_lo(rev64(x), rev64(y))) >> 1;
    (lo, hi)
}

/// Full 128×128 → 256 bit carry-less product of `a` and `b`.
///
/// Returns `(lo, hi)` such that the 256-bit product is `hi·2¹²⁸ + lo`.
#[inline(always)]
pub(crate) fn bmul128_full(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a as u64;
    let a_hi = (a >> 64) as u64;
    let b_lo = b as u64;
    let b_hi = (b >> 64) as u64;

    let (p00_lo, p00_hi) = bmul64_full(a_lo, b_lo);
    let (p11_lo, p11_hi) = bmul64_full(a_hi, b_hi);
    let (p01_lo, p01_hi) = bmul64_full(a_lo, b_hi);
    let (p10_lo, p10_hi) = bmul64_full(a_hi, b_lo);

    let mid_lo = p01_lo ^ p10_lo;
    let mid_hi = p01_hi ^ p10_hi;

    // Lay out the 256-bit result:
    //   p00 → bits [0..128]
    //   p11 → bits [128..256]
    //   mid_lo → bits [64..128]  (high half of `lo`)
    //   mid_hi → bits [128..192] (low half of `hi`)
    let p00 = ((p00_hi as u128) << 64) | (p00_lo as u128);
    let p11 = ((p11_hi as u128) << 64) | (p11_lo as u128);

    let lo = p00 ^ ((mid_lo as u128) << 64);
    let hi = p11 ^ (mid_hi as u128);

    (lo, hi)
}

#[cfg(test)]
mod tests {
    use super::{bmul64_full, bmul128_full, rev64};

    #[test]
    fn bmul64_identity_and_zero() {
        assert_eq!(bmul64_full(0, 0xDEADBEEFCAFEBABE), (0, 0));
        assert_eq!(bmul64_full(0xDEADBEEFCAFEBABE, 0), (0, 0));
        assert_eq!(bmul64_full(1, 0xDEADBEEFCAFEBABE), (0xDEADBEEFCAFEBABE, 0));
        assert_eq!(bmul64_full(0xDEADBEEFCAFEBABE, 1), (0xDEADBEEFCAFEBABE, 0));
    }

    #[test]
    fn bmul64_known_vectors() {
        // x · x = x², fits in low.
        assert_eq!(bmul64_full(2, 2), (4, 0));
        // x^63 · x = x^64 → low 64 empty, hi bit 0 set.
        assert_eq!(bmul64_full(1 << 63, 2), (0, 1));
        // x^63 · x^63 = x^126 → hi bit 62 set.
        assert_eq!(bmul64_full(1 << 63, 1 << 63), (0, 1 << 62));
        // (x^31 + … + 1)² = x^62 + x^60 + … + 1 (squaring in GF(2) just spreads
        // bits).
        assert_eq!(
            bmul64_full(0xFFFFFFFF, 0xFFFFFFFF),
            (0x5555_5555_5555_5555, 0)
        );
        // (x^63 + … + 1)² = x^126 + x^124 + … + 1 → bits 0,2,…,126.
        assert_eq!(
            bmul64_full(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
            (0x5555_5555_5555_5555, 0x5555_5555_5555_5555),
        );
    }

    #[test]
    fn rev64_involution() {
        for x in [0u64, 1, 0x8000_0000_0000_0000, 0xDEADBEEFCAFEBABE, !0] {
            assert_eq!(rev64(rev64(x)), x, "rev(rev({x:#x})) != {x:#x}");
        }
        assert_eq!(rev64(1), 1u64 << 63);
        assert_eq!(rev64(0x80_00_00_00_00_00_00_00), 1);
    }

    #[test]
    fn bmul128_identity_and_zero() {
        let big = 0xDEADBEEFCAFEBABE0123456789ABCDEFu128;
        assert_eq!(bmul128_full(0, big), (0, 0));
        assert_eq!(bmul128_full(big, 0), (0, 0));
        assert_eq!(bmul128_full(1, big), (big, 0));
        assert_eq!(bmul128_full(big, 1), (big, 0));
    }

    #[test]
    fn bmul128_known_vectors() {
        // x · x = x², fits in low.
        assert_eq!(bmul128_full(2, 2), (4, 0));
        // x^127 · x = x^128 → low empty, hi bit 0 set.
        assert_eq!(bmul128_full(1u128 << 127, 2), (0, 1));
        // x^127 · x^127 = x^254 → hi bit 126 set.
        assert_eq!(bmul128_full(1u128 << 127, 1u128 << 127), (0, 1u128 << 126));
        // 64-bit all-ones squared — (x^63 + … + 1)² = x^126 + x^124 + … + 1
        // → alternating bits 0, 2, …, 126 set, which fits entirely in low 128.
        assert_eq!(
            bmul128_full(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
            (0x55555555555555555555555555555555, 0),
        );
    }
}
