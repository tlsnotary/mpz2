use derive_builder::Builder;
use mpz_core::lpn::LpnParameters;
use std::{cmp::Reverse, fmt::Debug, ops::Range, sync::Arc};

mod regular;
pub use regular::LPN_PARAMS as REGULAR_PARAMS;

/// Computational security parameter.
pub(crate) const CSP: usize = 128;

#[cfg(test)]
pub(crate) const TEST_PARAMS: LpnParameters = LpnParameters {
    n: 9600,
    k: 1024,
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

/// The hold/pass sizing of one round of extension, see
/// [`FerretConfig::round_plan`].
pub(crate) struct RoundPlan {
    /// Base correlations consumed per round (`M`).
    pub cost: usize,
    /// Correlations handed to the user this round.
    pub user_len: usize,
    /// Trees whose output seeds the next round (`refill_trees`).
    pub refill_trees: usize,
    /// Size of the consistency-check group.
    csp: usize,
    /// Size of the LPN input.
    k: usize,
}

impl RoundPlan {
    /// Where this round's base-correlation groups sit in the tail.
    pub(crate) fn tail(&self, spcot_count: usize) -> TailLayout {
        #[cfg(feature = "emp")]
        let tail = TailLayout {
            spcot: spcot_count,
            check: (self.k + self.csp, self.k),
            lpn: (self.k, 0),
        };
        #[cfg(not(feature = "emp"))]
        let tail = TailLayout {
            spcot: spcot_count,
            check: (self.csp, 0),
            lpn: (self.k + self.csp, self.csp),
        };
        tail
    }
}

/// Placement of one round's base-correlation groups, counted back from the end
/// of the buffer that holds them.
pub(crate) struct TailLayout {
    /// Number of SPCOT blocks at the very end.
    spcot: usize,
    /// Check group as `(start, end)`, counted back from the end of the
    /// non-SPCOT part.
    check: (usize, usize),
    /// LPN group, likewise counted back from the end of the non-SPCOT part.
    lpn: (usize, usize),
}

impl TailLayout {
    fn range(&self, base: usize, (start, end): (usize, usize)) -> Range<usize> {
        base - start..base - end
    }

    /// Removes the three groups from `buffer`, returning `(spcot, check, lpn)`.
    pub(crate) fn split<T>(&self, buffer: &mut Vec<T>) -> (Vec<T>, Vec<T>, Vec<T>) {
        let base = buffer.len() - self.spcot;
        let mut groups = [
            (base..buffer.len(), 0usize),
            (self.range(base, self.check), 1),
            (self.range(base, self.lpn), 2),
        ];
        // Drain back to front so the remaining absolute offsets stay valid.
        groups.sort_unstable_by_key(|(range, _)| Reverse(range.start));
        let mut out: [Vec<T>; 3] = std::array::from_fn(|_| Vec::new());
        for (range, slot) in groups {
            out[slot] = buffer.drain(range).collect();
        }
        let [spcot, check, lpn] = out;
        (spcot, check, lpn)
    }

    /// Removes the check-group bits from a buffer holding the same layout
    /// without the SPCOT group (the receiver's choice bits).
    pub(crate) fn take_check_masks(&self, choices: &mut Vec<bool>) -> Vec<bool> {
        let len = choices.len();
        choices.drain(self.range(len, self.check)).collect()
    }
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
        #[cfg(feature = "emp")]
        {
            // One round's worth.
            iteration_cost(self.select_params(0, 0))
        }
        #[cfg(not(feature = "emp"))]
        {
            iteration_cost(REGULAR_PARAMS[0])
        }
    }

    /// Correlations held back as a reserve (never handed to the user).
    pub(crate) fn reserve(&self) -> usize {
        if self.reserve_bootstrap {
            self.bootstrap_cost()
        } else {
            0
        }
    }

    /// Sizes one round of extension for `params`.
    pub(crate) fn round_plan(&self, params: LpnParameters) -> RoundPlan {
        let cost = iteration_cost(params);
        let chunk = params.n / params.t;

        // Trees held back to seed the next round.
        #[cfg(feature = "emp")]
        let refill_trees = cost.div_ceil(chunk);
        #[cfg(not(feature = "emp"))]
        let refill_trees = 0;

        RoundPlan {
            cost,
            user_len: params.n - refill_trees * chunk,
            refill_trees,
            csp: CSP,
            k: params.k,
        }
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
    // In our chosen parameters, we always set n divisible by t and n/t is a
    // power of 2.
    assert!(params.n.is_multiple_of(params.t) && (params.n / params.t).is_power_of_two());
    params.t * ((params.n / params.t).ilog2() as usize) + params.k + CSP
}
