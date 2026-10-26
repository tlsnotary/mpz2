//! emp-ot compatibility surface.
//!
//! Compiled only with the `emp` feature. It holds everything that exists solely
//! to reproduce emp-ot byte-for-byte: the per-role state, the internal
//! derivations emp performs itself, and the wire adapters used by the golden
//! tests. The default build has none of it.

mod compat;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire;

pub(crate) use compat::lpn_seed;

use mpz_core::{Block, lpn::LpnParameters};
use mpz_fields::gf2_128::Gf2_128;

use super::config::RoundPlan;

/// emp-only sender state.
#[derive(Debug)]
pub(crate) struct EmpSender {
    /// Session id for the compat derivations.
    pub(crate) sid: Block,
    /// Next round's bases (this round's refill trees).
    next_keys: Vec<Gf2_128>,
}

impl EmpSender {
    pub(crate) fn new() -> Self {
        Self {
            sid: Block::ZERO,
            next_keys: Vec::new(),
        }
    }

    /// Appends the previous round's refill output to this round's bases.
    pub(crate) fn begin_round(&mut self, keys: &mut Vec<Gf2_128>) {
        keys.append(&mut self.next_keys);
    }

    /// Moves this round's refill output out of `keys`.
    pub(crate) fn take_refill(
        &mut self,
        keys: &mut Vec<Gf2_128>,
        plan: RoundPlan,
        params: LpnParameters,
    ) {
        let refill = plan.refill_trees * (params.n / params.t);
        self.next_keys = keys.split_off(keys.len() - refill);
        // Keep the first `M` of the refill output.
        self.next_keys.truncate(plan.cost);
    }
}

/// emp-only receiver state.
#[derive(Debug)]
pub(crate) struct EmpReceiver {
    /// Session id for the compat derivations.
    pub(crate) sid: Block,
    /// Next round's bases (this round's refill trees).
    next_macs: Vec<Gf2_128>,
    /// Next round's choice bits, alongside `next_macs`.
    next_choices: Vec<bool>,
}

impl EmpReceiver {
    pub(crate) fn new() -> Self {
        Self {
            sid: Block::ZERO,
            next_macs: Vec::new(),
            next_choices: Vec::new(),
        }
    }

    /// Appends the previous round's refill output to this round's bases.
    pub(crate) fn begin_round(&mut self, macs: &mut Vec<Gf2_128>, choices: &mut Vec<bool>) {
        macs.append(&mut self.next_macs);
        choices.append(&mut self.next_choices);
    }

    /// Moves this round's refill output out of `macs` and `choices`.
    pub(crate) fn take_refill(
        &mut self,
        macs: &mut Vec<Gf2_128>,
        choices: &mut Vec<bool>,
        plan: RoundPlan,
        params: LpnParameters,
    ) {
        let refill = plan.refill_trees * (params.n / params.t);
        self.next_macs = macs.split_off(macs.len() - refill);
        self.next_choices = choices.split_off(choices.len() - refill);
        // Keep the first `M` of the refill output.
        self.next_macs.truncate(plan.cost);
        self.next_choices.truncate(plan.cost);
    }
}
