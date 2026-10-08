//! Vector oblivious polynomial evaluation (VOPE) protocol for degree 1.
//!
//! This implementation is specifically for degree 1, i.e. VOLE over the
//! extension field.

use itybity::FromBitIterator;
use mpz_core::Block;

/// Computes extension field VOLE share as the sender.
///
/// Returns `B` from figure 4.
///
/// # Arguments
///
/// * `keys` - Keys from subfield VOLE.
pub fn vole_sender(keys: &[Block; 128]) -> Block {
    Block::inn_prdt_red(keys, &Block::MONOMIAL)
}

/// Computes extension field VOLE share as the receiver.
///
/// Returns `A_0` and `A_1` from figure 4, respectively.
///
/// # Arguments
///
/// * `choices` - Choices from subfield VOLE.
/// * `ev` - Evaluations from subfield VOLE.
pub fn vole_receiver(choices: &[bool; 128], ev: &[Block; 128]) -> (Block, Block) {
    let a_0 = Block::inn_prdt_red(ev, &Block::MONOMIAL);
    let a_1 = Block::from_lsb0_iter(choices.iter().copied());

    (a_0, a_1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_memory_core::correlated::Delta;
    use mpz_ot_core::{
        ideal::rcot::IdealRCOT,
        rcot::{RCOTReceiverOutput, RCOTSenderOutput},
    };
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    #[test]
    fn test_vole() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let mut rcot = IdealRCOT::new(rng.random(), delta.into_inner());

        rcot.alloc(128);
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput { keys, .. },
            RCOTReceiverOutput {
                choices, msgs: ev, ..
            },
        ) = rcot.transfer(128).unwrap();

        let b = vole_sender(&keys.try_into().unwrap());
        let (a_0, a_1) = vole_receiver(&choices.try_into().unwrap(), &ev.try_into().unwrap());

        assert_eq!(b, a_1.gfmul(*delta.as_block()) ^ a_0);
    }
}
