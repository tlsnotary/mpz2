//! Runtime backend selection for GF(2¹²⁸) on x86_64 built without
//! compile-time PCLMULQDQ: each operation dispatches to the intrinsics
//! backend when the CPU supports carry-less multiplication, falling back
//! to the portable software backend otherwise.
#![allow(unsafe_code)]

use super::{Gf2_128, soft, x86};

cpufeatures::new!(cpuid_pclmulqdq, "pclmulqdq");

#[inline(always)]
fn has_pclmulqdq() -> bool {
    cpuid_pclmulqdq::get()
}

#[inline]
pub(super) fn mul(a: u128, b: u128) -> u128 {
    if has_pclmulqdq() {
        // SAFETY: PCLMULQDQ support was detected at runtime.
        unsafe { x86::mul(a, b) }
    } else {
        soft::mul(a, b)
    }
}

#[inline]
pub(super) fn mul_full(a: u128, b: u128) -> (u128, u128) {
    if has_pclmulqdq() {
        // SAFETY: PCLMULQDQ support was detected at runtime.
        unsafe { x86::mul_full(a, b) }
    } else {
        soft::mul_full(a, b)
    }
}

#[inline]
pub(super) fn reduce(lo: u128, hi: u128) -> u128 {
    if has_pclmulqdq() {
        // SAFETY: PCLMULQDQ support was detected at runtime.
        unsafe { x86::reduce(lo, hi) }
    } else {
        soft::reduce(lo, hi)
    }
}

/// The x86 squaring path is pure scalar bit-spread and needs no CPU
/// feature, but routing through the dispatch keeps both backends in use.
#[inline]
pub(super) fn square(a: u128) -> u128 {
    if has_pclmulqdq() {
        x86::square(a)
    } else {
        soft::square(a)
    }
}

#[inline]
pub(super) fn inverse(a: u128) -> u128 {
    if has_pclmulqdq() {
        // SAFETY: PCLMULQDQ support was detected at runtime.
        unsafe { x86::inverse(a) }
    } else {
        soft::inverse(a)
    }
}

#[inline]
pub(super) fn inner_product(a: &[Gf2_128], b: &[Gf2_128]) -> u128 {
    if has_pclmulqdq() {
        // SAFETY: PCLMULQDQ support was detected at runtime.
        unsafe { x86::inner_product(a, b) }
    } else {
        soft::inner_product(a, b)
    }
}

#[inline]
pub(super) fn double_inner_product(a: &[Gf2_128], b: &[Gf2_128], c: &[Gf2_128]) -> u128 {
    if has_pclmulqdq() {
        // SAFETY: PCLMULQDQ support was detected at runtime.
        unsafe { x86::double_inner_product(a, b, c) }
    } else {
        soft::double_inner_product(a, b, c)
    }
}
