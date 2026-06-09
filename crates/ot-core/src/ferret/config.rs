use derive_builder::Builder;
use mpz_core::lpn::LpnParameters;
use std::{fmt::Debug, sync::Arc};

mod regular;
pub use regular::LPN_PARAMS as REGULAR_PARAMS;

/// Computational security parameter.
pub(crate) const CSP: usize = 128;

#[cfg(test)]
pub(crate) const TEST_PARAMS: LpnParameters = LpnParameters {
    n: 9600,
    k: 1220,
    t: 600,
};

/// Ferret configuration.
#[derive(Clone, Builder)]
pub struct FerretConfig {
    /// Whether to reserve bootstrap COTs.
    #[builder(default = "true")]
    reserve_bootstrap: bool,
    #[builder(setter(custom), default = "Arc::new(default_parameter_selector)")]
    param_selector: Arc<dyn Fn(usize, usize) -> LpnParameters + Send + Sync + 'static>,
}

impl Debug for FerretConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FerretConfig")
            .field("reserve_bootstrap", &self.reserve_bootstrap)
            .finish_non_exhaustive()
    }
}

impl Default for FerretConfig {
    fn default() -> Self {
        Self {
            reserve_bootstrap: true,
            param_selector: Arc::new(default_parameter_selector),
        }
    }
}

impl FerretConfigBuilder {
    /// Configures the LPN parameter selector.
    ///
    /// The provided function must have the following signature:
    ///
    /// `(available, additional) -> LpnParameters`
    ///
    /// where `available` is the current number of available COTs and
    /// `additional` is the number of COTs that still need to be generated.
    pub fn param_selector<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(usize, usize) -> LpnParameters + Send + Sync + 'static,
    {
        self.param_selector = Some(Arc::new(f));
        self
    }
}

impl FerretConfig {
    /// Returns a new `FerretConfigBuilder`.
    pub fn builder() -> FerretConfigBuilder {
        FerretConfigBuilder::default()
    }

    /// Returns `true` if bootstrap COTs should be reserved.
    pub fn reserve_bootstrap(&self) -> bool {
        self.reserve_bootstrap
    }

    /// Returns the cost of a bootstrap iteration.
    pub(crate) fn bootstrap_cost(&self) -> usize {
        iteration_cost(REGULAR_PARAMS[0])
    }

    pub(crate) fn select_params(&self, available: usize, additional: usize) -> LpnParameters {
        (self.param_selector)(available, additional)
    }
}

fn default_parameter_selector(available: usize, additional: usize) -> LpnParameters {
    // *Assumes the parameters are in ascending order.*
    let mut last_valid_param = REGULAR_PARAMS[0];
    for param in REGULAR_PARAMS {
        let cost = iteration_cost(*param);
        let net = param.n - cost;

        // Only selects params for which we have enough OTs available.
        if available < cost {
            return last_valid_param;
        } else {
            last_valid_param = *param;
        }

        // Returns the smallest params that satisfy the additionally requested
        // amount.
        if net >= additional {
            return *param;
        }
    }

    // If we reach here, we select the largest parameters.
    *REGULAR_PARAMS.last().unwrap()
}

/// Returns the number of COTs needed to execute an iteration with the given
/// parameters.
fn iteration_cost(params: LpnParameters) -> usize {
    // In our chosen parameters, we always set n divisible by t and n/t is a power of 2.
    assert!(params.n.is_multiple_of(params.t) && (params.n / params.t).is_power_of_two());
    params.t * ((params.n / params.t).ilog2() as usize) + params.k + CSP
}
