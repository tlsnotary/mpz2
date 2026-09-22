//! CarryLess MULtiplication (clmul) based on the crate:
//! https://github.com/RustCrypto/universal-hashes/tree/master/polyval
//!
//! Only those comments from the original file are preserved which are relevant
//! to carryless multiplication.
//!
//! # Minimum Supported Rust Version
//! Rust **1.56** or higher.
//!
//! # Supported backends
//! This crate provides multiple backends including a portable pure Rust
//! backend as well as ones based on CPU intrinsics.
//!
//! ## "soft" portable backend
//! As a baseline implementation, this crate provides a constant-time pure Rust
//! implementation based on [BearSSL], which is a straightforward and
//! compact implementation which uses a clever but simple technique to avoid
//! carry-spilling.
//!
//! Usage of the soft-backend can be forced by setting the `clmul_force_soft`
//! RUSTFLAG.
//!
//! ```text
//! $ RUSTFLAGS="--cfg clmul_force_soft" cargo bench
//! ```
//!
//! ## ARMv8 intrinsics (`PMULL`, nightly-only)
//! On `aarch64` targets including `aarch64-apple-darwin` (Apple M1) and Linux
//! targets such as `aarch64-unknown-linux-gnu` and
//! `aarch64-unknown-linux-musl`, support for using the `PMULL` instructions in
//! ARMv8's Cryptography Extensions is available when using the nightly
//! compiler, and can be enabled using the `clmul_armv8` RUSTFLAG.
//!
//! ```text
//! $ RUSTFLAGS="--cfg clmul_armv8" cargo bench
//! ```
//!
//! On Linux and macOS, when the `clmul_armv8` RUSTFLAG is enabled support for
//! AES intrinsics is autodetected at runtime.
//!
//! ## `x86`/`x86_64` intrinsics (`CMLMUL`)
//! By default this crate uses runtime detection on `i686`/`x86_64` targets
//! in order to determine if `CLMUL` is available, and if it is not, it will
//! fallback to using a constant-time software implementation.
//!
//! For optimal performance, set `target-cpu` in `RUSTFLAGS` to `sandybridge`
//! or newer:
//!
//! Example:
//!
//! ```text
//! $ RUSTFLAGS="-Ctarget-cpu=sandybridge" cargo bench
//! ```

#![cfg_attr(not(test), no_std)]
#![cfg_attr(all(clmul_armv8, target_arch = "aarch64"), feature(stdsimd))]

mod backend;
pub use backend::Clmul;

#[cfg(test)]
#[path = ""]
mod tests {
    #[path = "backend/soft32.rs"]
    mod soft32;

    #[path = "backend/soft64.rs"]
    mod soft64;

    #[test]
    #[cfg(not(clmul_force_soft))]
    // test backends against each other
    fn clmul_test() {
        use rand::RngExt;
        use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};

        // test soft backends
        use soft32::Clmul as s32;
        use soft64::Clmul as s64;

        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: [u8; 16] = rng.random();
        let b: [u8; 16] = rng.random();

        let (r64_0, r64_1) = s64::new(&a).clmul(s64::new(&b));
        let (r32_0, r32_1) = s32::new(&a).clmul(s32::new(&b));
        let r64_0: [u8; 16] = r64_0.into();
        let r64_1: [u8; 16] = r64_1.into();
        let r32_0: [u8; 16] = r32_0.into();
        let r32_1: [u8; 16] = r32_1.into();
        assert_eq!(r64_0, r32_0);
        assert_eq!(r64_1, r32_1);

        use super::Clmul;

        let (c, d) = Clmul::new(&a).clmul(Clmul::new(&b));
        let c: [u8; 16] = c.into();
        let d: [u8; 16] = d.into();
        assert_eq!(r64_0, c);
        assert_eq!(r64_1, d);
    }

    #[test]
    // test soft32 backend
    fn clmul_xor_eq_soft32() {
        use soft32::Clmul;

        let mut one = [0u8; 16];
        one[15] = 1;
        let mut two = [0u8; 16];
        two[15] = 2;
        let mut three = [0u8; 16];
        three[15] = 3;
        let mut six = [0u8; 16];
        six[15] = 6;

        let a1 = Clmul::new(&one);
        let a2 = Clmul::new(&two);
        let a3 = Clmul::new(&three);
        let a6 = Clmul::new(&six);

        assert!(a1 ^ a2 == a3);
        assert!(a1 ^ a6 != a3);

        let b = a1.clmul(a6);
        let c = a2.clmul(a3);
        let d = a3.clmul(a6);
        assert!(b.0 == c.0);
        assert!(b.1 == c.1);
        // d.0 is zero
        assert!(b.1 != d.1);
    }

    #[test]
    // test soft64 backend
    fn clmul_xor_eq_soft64() {
        use soft64::Clmul;

        let mut one = [0u8; 16];
        one[15] = 1;
        let mut two = [0u8; 16];
        two[15] = 2;
        let mut three = [0u8; 16];
        three[15] = 3;
        let mut six = [0u8; 16];
        six[15] = 6;

        let a1 = Clmul::new(&one);
        let a2 = Clmul::new(&two);
        let a3 = Clmul::new(&three);
        let a6 = Clmul::new(&six);

        assert!(a1 ^ a2 == a3);
        assert!(a1 ^ a6 != a3);

        let b = a1.clmul(a6);
        let c = a2.clmul(a3);
        let d = a3.clmul(a6);
        assert!(b.0 == c.0);
        assert!(b.1 == c.1);
        // d.0 is zero
        assert!(b.1 != d.1);
    }

    #[test]
    #[cfg(not(clmul_force_soft))]
    fn clmul_xor_eq_hard() {
        use super::Clmul;

        let mut one = [0u8; 16];
        one[15] = 1;
        let mut two = [0u8; 16];
        two[15] = 2;
        let mut three = [0u8; 16];
        three[15] = 3;
        let mut six = [0u8; 16];
        six[15] = 6;

        let a1 = Clmul::new(&one);
        let a2 = Clmul::new(&two);
        let a3 = Clmul::new(&three);
        let a6 = Clmul::new(&six);

        assert!(a1 ^ a2 == a3);
        assert!(a1 ^ a6 != a3);

        let b = a1.clmul(a6);
        let c = a2.clmul(a3);
        let d = a3.clmul(a6);
        assert!(b.0 == c.0);
        assert!(b.1 == c.1);
        // d.0 is zero
        assert!(b.1 != d.1);
    }

    #[test]
    // Test against test vectors from
    // Intel® Carry-Less Multiplication Instruction and its Usage for Computing
    // the GCM Mode
    fn clmul_test_vectors() {
        use super::backend::Clmul;

        let xmm1_high: [u8; 16] = 0x7b5b546573745665_u128.to_le_bytes();
        let xmm1_low: [u8; 16] = 0x63746f725d53475d_u128.to_le_bytes();
        let xmm2_high: [u8; 16] = 0x4869285368617929_u128.to_le_bytes();
        let xmm2_low: [u8; 16] = 0x5b477565726f6e5d_u128.to_le_bytes();

        assert_eq!(
            Clmul::new(&xmm2_low).clmul(Clmul::new(&xmm1_low)),
            (
                Clmul::new(&0x1d4d84c85c3440c0929633d5d36f0451_u128.to_le_bytes()),
                Clmul::new(&[0u8; 16]),
            ),
        );

        assert_eq!(
            Clmul::new(&xmm2_high).clmul(Clmul::new(&xmm1_low)),
            (
                Clmul::new(&0x1bd17c8d556ab5a17fa540ac2a281315_u128.to_le_bytes()),
                Clmul::new(&[0u8; 16]),
            ),
        );

        assert_eq!(
            Clmul::new(&xmm2_low).clmul(Clmul::new(&xmm1_high)),
            (
                Clmul::new(&0x1a2bf6db3a30862fbabf262df4b7d5c9_u128.to_le_bytes()),
                Clmul::new(&[0u8; 16]),
            ),
        );

        assert_eq!(
            Clmul::new(&xmm2_high).clmul(Clmul::new(&xmm1_high)),
            (
                Clmul::new(&0x1d1e1f2c592e7c45d66ee03e410fd4ed_u128.to_le_bytes()),
                Clmul::new(&[0u8; 16]),
            ),
        );

        let xmm1 = 0x00000000000000008000000000000000_u128.to_le_bytes();
        let xmm2 = 0x00000000000000008000000000000000_u128.to_le_bytes();
        let result = 0x40000000000000000000000000000000_u128.to_le_bytes();
        assert_eq!(
            Clmul::new(&xmm1).clmul(Clmul::new(&xmm2)),
            (Clmul::new(&result), Clmul::new(&[0u8; 16])),
        );
    }
}
