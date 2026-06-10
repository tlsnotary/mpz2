//! Tooling to analyse the bit-security of LPN parameters.
//!
//! This crate no longer generates parameter tables. It only exposes
//! [`LpnEstimator`], used to *confirm* the security level of a chosen
//! `(n, k, t)` instance. See the `regular` and `exact` binaries.

mod lpn;

pub use lpn::LpnEstimator;
