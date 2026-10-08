//! Autodetection for CPU intrinsics, with fallback to the "soft" backend when
//! they are unavailable.

use core::ops::{BitXor, BitXorAssign};

use crate::backend::soft;

#[cfg(all(target_arch = "aarch64", clmul_armv8))]
use super::pmull as intrinsics;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use super::clmul as intrinsics;

#[cfg(all(target_arch = "aarch64", clmul_armv8))]
cpufeatures::new!(mul_intrinsics, "aes"); // `aes` implies PMULL

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
cpufeatures::new!(mul_intrinsics, "pclmulqdq");

/// Carryless multiplication
#[derive(Clone, Copy)]
pub struct Clmul {
    inner: Inner,
    token: mul_intrinsics::InitToken,
}

#[derive(Clone, Copy)]
union Inner {
    intrinsics: intrinsics::Clmul,
    soft: soft::Clmul,
}

impl mul_intrinsics::InitToken {
    #[inline(always)]
    fn get_intr(&self) -> bool {
        !cfg!(clmul_force_soft) && self.get()
    }
}

impl core::fmt::Debug for Clmul {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unsafe {
            if self.token.get_intr() {
                self.inner.intrinsics.fmt(f)
            } else {
                self.inner.soft.fmt(f)
            }
        }
    }
}

impl Clmul {
    pub fn new(h: &[u8; 16]) -> Self {
        let (token, has_intrinsics) = mul_intrinsics::init_get();

        let inner = if cfg!(clmul_force_soft) || !has_intrinsics {
            Inner {
                soft: soft::Clmul::new(h),
            }
        } else {
            Inner {
                intrinsics: intrinsics::Clmul::new(h),
            }
        };

        Self { inner, token }
    }

    /// Performs carryless multiplication
    #[inline]
    pub fn clmul(self, x: Self) -> (Self, Self) {
        unsafe {
            let (in0, in1) = if self.token.get_intr() {
                let s_intr = self.inner.intrinsics;
                let x_intr = x.inner.intrinsics;

                let (r0, r1) = s_intr.clmul(x_intr);
                (Inner { intrinsics: r0 }, Inner { intrinsics: r1 })
            } else {
                let s_soft = self.inner.soft;
                let x_soft = x.inner.soft;

                let (r0, r1) = s_soft.clmul(x_soft);
                (Inner { soft: r0 }, Inner { soft: r1 })
            };

            (
                Self {
                    inner: in0,
                    token: self.token,
                },
                Self {
                    inner: in1,
                    token: x.token,
                },
            )
        }
    }

    /// Reduces the polynomial represented in bits modulo the GCM polynomial
    /// x^128 + x^7 + x^2 + x + 1. x and y are resp. upper and lower bits of
    /// the polynomial.
    #[inline]
    pub fn reduce_gcm(x: Self, y: Self) -> Self {
        unsafe {
            if x.token.get_intr() {
                let x_intr = x.inner.intrinsics;
                let y_intr = y.inner.intrinsics;

                let r = intrinsics::Clmul::reduce_gcm(x_intr, y_intr);
                Self {
                    inner: Inner { intrinsics: r },
                    token: x.token,
                }
            } else {
                let x_soft = x.inner.soft;
                let y_soft = y.inner.soft;

                let r = soft::Clmul::reduce_gcm(x_soft, y_soft);
                Self {
                    inner: Inner { soft: r },
                    token: x.token,
                }
            }
        }
    }
}

impl From<Clmul> for [u8; 16] {
    #[inline]
    fn from(m: Clmul) -> [u8; 16] {
        unsafe {
            if m.token.get_intr() {
                m.inner.intrinsics.into()
            } else {
                m.inner.soft.into()
            }
        }
    }
}

impl BitXor for Clmul {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        unsafe {
            let inner = if self.token.get_intr() {
                let a = self.inner.intrinsics;
                let b = other.inner.intrinsics;
                Inner { intrinsics: a ^ b }
            } else {
                let a = self.inner.soft;
                let b = other.inner.soft;
                Inner { soft: a ^ b }
            };

            Self {
                inner,
                token: self.token,
            }
        }
    }
}

impl BitXorAssign for Clmul {
    #[inline]
    fn bitxor_assign(&mut self, other: Self) {
        unsafe {
            if self.token.get_intr() {
                let a = self.inner.intrinsics;
                let b = other.inner.intrinsics;
                self.inner.intrinsics = a ^ b;
            } else {
                let a = self.inner.soft;
                let b = other.inner.soft;
                self.inner.soft = a ^ b;
            }
        }
    }
}

impl PartialEq for Clmul {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            if self.token.get_intr() {
                self.inner.intrinsics == other.inner.intrinsics
            } else {
                self.inner.soft == other.inner.soft
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_test() {
        use rand::RngExt;
        use rand_chacha::{ChaCha12Rng, rand_core::SeedableRng};

        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let x: [u8; 16] = rng.random();
        let y: [u8; 16] = rng.random();

        let xx = soft::Clmul::new(&x);
        let yy = soft::Clmul::new(&y);

        let zz = soft::Clmul::reduce_gcm(xx, yy);
        let zz: [u8; 16] = zz.into();

        let xxx = Clmul::new(&x);
        let yyy = Clmul::new(&y);

        let zzz = Clmul::reduce_gcm(xxx, yyy);
        let zzz: [u8; 16] = zzz.into();

        assert_eq!(zz, zzz);
    }
}
