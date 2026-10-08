//! Intel `CLMUL`-accelerated implementation for modern x86/x86_64 CPUs
//! (i.e. Intel Sandy Bridge-compatible or newer)

use core::ops::BitXor;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub type Clmul = ClmulX86;

#[derive(Clone, Copy, Debug)]
pub struct ClmulX86(pub __m128i);

impl From<ClmulX86> for [u8; 16] {
    #[inline]
    fn from(m: ClmulX86) -> [u8; 16] {
        unsafe {
            let b: [u8; 16] = core::mem::transmute(m);
            b
        }
    }
}

impl BitXor for ClmulX86 {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        unsafe { Self(_mm_xor_si128(self.0, other.0)) }
    }
}

impl PartialEq for ClmulX86 {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            u128::from_le_bytes(core::mem::transmute::<__m128i, [u8; 16]>(self.0))
                == u128::from_le_bytes(core::mem::transmute::<__m128i, [u8; 16]>(other.0))
        }
    }
}

impl ClmulX86 {
    /// expects bytes in little-endian
    pub fn new(bytes: &[u8; 16]) -> Self {
        unsafe {
            // `_mm_loadu_si128` performs an unaligned load
            #[allow(clippy::cast_ptr_alignment)]
            Self(_mm_loadu_si128(bytes.as_ptr() as *const __m128i))
        }
    }

    #[inline]
    pub fn clmul(self, x: Self) -> (ClmulX86, ClmulX86) {
        unsafe { self.clmul_unsafe(x) }
    }

    #[inline]
    #[target_feature(enable = "pclmulqdq")]
    unsafe fn clmul_unsafe(self, x: Self) -> (ClmulX86, ClmulX86) {
        let h = self.0;
        let y = x.0;

        let h0 = h;
        let h1 = _mm_shuffle_epi32(h, 0x0E);
        let h2 = _mm_xor_si128(h0, h1);
        let y0 = y;

        // Multiply values partitioned to 64-bit parts
        let y1 = _mm_shuffle_epi32(y, 0x0E);
        let y2 = _mm_xor_si128(y0, y1);
        let t0 = _mm_clmulepi64_si128(y0, h0, 0x00);
        let t1 = _mm_clmulepi64_si128(y, h, 0x11);
        let t2 = _mm_clmulepi64_si128(y2, h2, 0x00);
        let t2 = _mm_xor_si128(t2, _mm_xor_si128(t0, t1));
        let v0 = t0;
        let v1 = _mm_xor_si128(_mm_shuffle_epi32(t0, 0x0E), t2);
        let v2 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
        let v3 = _mm_shuffle_epi32(t1, 0x0E);

        (
            ClmulX86(_mm_unpacklo_epi64(v0, v1)),
            ClmulX86(_mm_unpacklo_epi64(v2, v3)),
        )
    }

    #[inline(always)]
    pub fn reduce_gcm(x: Self, y: Self) -> ClmulX86 {
        unsafe { Self::reduce_gcm_unsafe(&x, &y) }
    }

    // This implementation is adapted from EMP Toolkit.
    #[inline]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe fn reduce_gcm_unsafe(x: &Self, y: &Self) -> ClmulX86 {
        unsafe {
            let tmp3 = x.0;
            let tmp6 = y.0;
            let xmmmask = _mm_setr_epi32(-1, 0x0, 0x0, 0x0);
            let tmp7 = _mm_srli_epi32(tmp6, 31);
            let tmp8 = _mm_srli_epi32(tmp6, 30);
            let tmp9 = _mm_srli_epi32(tmp6, 25);

            let tmp7 = _mm_xor_si128(tmp7, tmp8);
            let tmp7 = _mm_xor_si128(tmp7, tmp9);

            let tmp8 = _mm_shuffle_epi32(tmp7, 147);

            let tmp7 = _mm_and_si128(xmmmask, tmp8);
            let tmp8 = _mm_andnot_si128(xmmmask, tmp8);
            let tmp3 = _mm_xor_si128(tmp3, tmp8);
            let tmp6 = _mm_xor_si128(tmp6, tmp7);

            let tmp10 = _mm_slli_epi32(tmp6, 1);
            let tmp3 = _mm_xor_si128(tmp3, tmp10);
            let tmp11 = _mm_slli_epi32(tmp6, 2);
            let tmp3 = _mm_xor_si128(tmp3, tmp11);
            let tmp12 = _mm_slli_epi32(tmp6, 7);
            let tmp3 = _mm_xor_si128(tmp3, tmp12);

            ClmulX86(_mm_xor_si128(tmp3, tmp6))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ClmulX86;
    use rand::RngExt;
    use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};
    use std::arch::x86_64::*;

    /// Carryless multiplication. Reference implementation.
    ///
    /// This code was adapted from swanky
    /// https://github.com/GaloisInc/swanky/blob/ac7d5d1e8286bbcddcdaf5501d5d925fe79d0591/scuttlebutt/src/block.rs#L51
    /// which in turn adapted it from the EMP toolkit's implementation.
    fn clmul128(a: u128, b: u128) -> (u128, u128) {
        unsafe {
            let x = std::mem::transmute::<u128, std::arch::x86_64::__m128i>(a);
            let y = std::mem::transmute::<u128, std::arch::x86_64::__m128i>(b);
            let zero = _mm_clmulepi64_si128(x, y, 0x00);
            let one = _mm_clmulepi64_si128(x, y, 0x10);
            let two = _mm_clmulepi64_si128(x, y, 0x01);
            let three = _mm_clmulepi64_si128(x, y, 0x11);
            let tmp = _mm_xor_si128(one, two);
            let ll = _mm_slli_si128(tmp, 8);
            let rl = _mm_srli_si128(tmp, 8);
            let x = _mm_xor_si128(zero, ll);
            let y = _mm_xor_si128(three, rl);
            let x_le: [u8; 16] = std::mem::transmute(x);
            let y_le: [u8; 16] = std::mem::transmute(y);
            (u128::from_le_bytes(x_le), u128::from_le_bytes(y_le))
        }
    }

    #[test]
    fn test_against_emptool_impl() {
        if !is_x86_feature_detected!("pclmulqdq") {
            return;
        }

        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: [u8; 16] = rng.random();
        let b: [u8; 16] = rng.random();

        let (r_0, r_1) = ClmulX86::new(&a).clmul(ClmulX86::new(&b));
        let (ref_0, ref_1) = clmul128(u128::from_le_bytes(a), u128::from_le_bytes(b));
        let r_0: [u8; 16] = r_0.into();
        let r_1: [u8; 16] = r_1.into();
        assert_eq!(r_0, ref_0.to_le_bytes());
        assert_eq!(r_1, ref_1.to_le_bytes());
    }
}
