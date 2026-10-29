//! Regular-LPN parameters for Ferret, from EMP-OT's `ferret_b10`..`ferret_b13`
//! (<https://github.com/emp-toolkit/emp-ot>). Each uses
//! `k = 2^logk = 64 * (n / t)`, tuned to ~128-bit security; verify with
//! `lpn-estimator`'s `regular` binary.
use mpz_core::lpn::LpnParameters;

/// LPN parameters, in ascending order of output size `n`.
pub static LPN_PARAMS: &[LpnParameters] = &[
    LpnParameters {
        n: 870400,
        k: 65536,
        t: 850,
    },
    LpnParameters {
        n: 2396160,
        k: 131072,
        t: 1170,
    },
    LpnParameters {
        n: 6225920,
        k: 262144,
        t: 1520,
    },
    LpnParameters {
        n: 15564800,
        k: 524288,
        t: 1900,
    },
];
