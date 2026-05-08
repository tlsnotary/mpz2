//! Autodetection for CPU intrinsics, with fallback to the "soft" backend when
//! they are unavailable.

use cfg_if::cfg_if;

#[allow(clippy::duplicate_mod)]
#[cfg_attr(not(target_pointer_width = "64"), path = "backend/soft32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "backend/soft64.rs")]
mod soft;

impl soft::Clmul {
    /// Reduces the polynomial represented in bits modulo the GCM polynomial
    /// x^128 + x^7 + x^2 + x + 1. x and y are resp. upper and lower bits of
    /// the polynomial.
    ///
    /// Page 16 of [Intel® Carry-Less Multiplication Instruction and its Usage
    /// for Computing the GCM Mode rev 2.02] (https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf)
    pub fn reduce_gcm(x: Self, y: Self) -> Self {
        fn sep(x: u128) -> (u64, u64) {
            // (high, low)
            ((x >> 64) as u64, x as u64)
        }
        fn join(u: u64, l: u64) -> u128 {
            ((u as u128) << 64) | (l as u128)
        }

        let x: u128 = zerocopy::transmute!(x);
        let y: u128 = zerocopy::transmute!(y);

        let (x3, x2) = sep(y);
        let (x1, x0) = sep(x);
        let a = x3 >> 63;
        let b = x3 >> 62;
        let c = x3 >> 57;
        let d = x2 ^ a ^ b ^ c;
        let (e1, e0) = sep(join(x3, d) << 1);
        let (f1, f0) = sep(join(x3, d) << 2);
        let (g1, g0) = sep(join(x3, d) << 7);
        let h1 = x3 ^ e1 ^ f1 ^ g1;
        let h0 = d ^ e0 ^ f0 ^ g0;
        zerocopy::transmute!(join(x1 ^ h1, x0 ^ h0))
    }
}

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", clmul_armv8, not(clmul_force_soft)))] {
        mod autodetect;
        mod pmull;
        pub use crate::backend::autodetect::Clmul;
    } else if #[cfg(
        all(
            any(target_arch = "x86_64", target_arch = "x86"),
            not(clmul_force_soft)
        )
    )] {
        mod autodetect;
        mod clmul;
        pub use crate::backend::autodetect::Clmul;
    } else {
        pub use crate::backend::soft::Clmul;
    }
}
