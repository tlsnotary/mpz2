//! Memory stores.

mod evaluator;
mod garbler;

pub use evaluator::{EvaluatorStore, EvaluatorStoreError};
pub use garbler::{GarblerStore, GarblerStoreError};

use blake3::Hash;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::correlated::{Mac, MacCommitment};
use serde::{Deserialize, Serialize};

/// Flush message sent by the garbler.
#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "validation::GarblerFlushUnchecked")]
pub struct GarblerFlush {
    /// MACs sent directly to the evaluator.
    macs: Vec<Mac>,
    /// Key bits for decoding.
    key_bits: BitVec,
    /// MAC commitments sent for decoding.
    mac_commitments: Vec<MacCommitment>,
}

/// Flush message sent by the evaluator.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluatorFlush {
    /// Proof of MACs for decoding.
    mac_proof: Option<MacProof>,
}

/// MAC proof sent from the evaluator to the garbler to prove
/// the output of a circuit.
#[derive(Debug, Serialize, Deserialize)]
pub struct MacProof {
    bits: BitVec,
    proof: Hash,
}

mod validation {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub(super) struct GarblerFlushUnchecked {
        pub macs: Vec<Mac>,
        pub key_bits: BitVec,
        pub mac_commitments: Vec<MacCommitment>,
    }

    impl TryFrom<GarblerFlushUnchecked> for GarblerFlush {
        type Error = String;

        fn try_from(value: GarblerFlushUnchecked) -> Result<Self, Self::Error> {
            let GarblerFlushUnchecked {
                macs,
                key_bits,
                mac_commitments,
            } = value;

            if mac_commitments.len() != key_bits.len() {
                return Err("garbler sent flush with invalid number of MAC commitments".to_string());
            }

            Ok(GarblerFlush {
                macs,
                key_bits,
                mac_commitments,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use mpz_core::Block;
    use mpz_memory_core::{
        Array, Memory, MemoryExt, ViewExt,
        binary::U8,
        correlated::{Delta, Key},
    };
    use mpz_ot_core::ideal::cot::IdealCOT;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;

    #[test]
    fn test_store_decode() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let cot = IdealCOT::new(delta.into_inner());

        let mut gb = GarblerStore::new(rng.random(), delta, cot.clone());
        let mut ev = EvaluatorStore::new(cot);

        let val_a = [0u8; 16];
        let val_b = [42u8; 16];
        let val_c = [69u8; 16];

        let ref_a_gb: Array<U8, 16> = gb.alloc().unwrap();
        gb.mark_public(ref_a_gb).unwrap();
        let ref_b_gb: Array<U8, 16> = gb.alloc().unwrap();
        gb.mark_private(ref_b_gb).unwrap();
        let ref_c_gb: Array<U8, 16> = gb.alloc().unwrap();
        gb.mark_blind(ref_c_gb).unwrap();

        let ref_a_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_public(ref_a_ev).unwrap();
        let ref_b_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_blind(ref_b_ev).unwrap();
        let ref_c_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_private(ref_c_ev).unwrap();

        gb.assign(ref_a_gb, val_a).unwrap();
        gb.assign(ref_b_gb, val_b).unwrap();

        ev.assign(ref_a_ev, val_a).unwrap();
        ev.assign(ref_c_ev, val_c).unwrap();

        gb.commit(ref_a_gb).unwrap();
        gb.commit(ref_b_gb).unwrap();
        gb.commit(ref_c_gb).unwrap();

        ev.commit(ref_a_ev).unwrap();
        ev.commit(ref_b_ev).unwrap();
        ev.commit(ref_c_ev).unwrap();

        assert!(gb.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gb.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gb.acquire_cot().flush().unwrap();

        gb.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

        let mut fut_a_gb = gb.decode(ref_a_gb).unwrap();
        let mut fut_b_gb = gb.decode(ref_b_gb).unwrap();
        let mut fut_c_gb = gb.decode(ref_c_gb).unwrap();

        let mut fut_a_ev = ev.decode(ref_a_ev).unwrap();
        let mut fut_b_ev = ev.decode(ref_b_ev).unwrap();
        let mut fut_c_ev = ev.decode(ref_c_ev).unwrap();

        assert!(gb.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gb.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gb.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

        let (val_a_gb, val_b_gb, val_c_gb) = (
            fut_a_gb.try_recv().unwrap().unwrap(),
            fut_b_gb.try_recv().unwrap().unwrap(),
            fut_c_gb.try_recv().unwrap().unwrap(),
        );

        let (val_a_ev, val_b_ev, val_c_ev) = (
            fut_a_ev.try_recv().unwrap().unwrap(),
            fut_b_ev.try_recv().unwrap().unwrap(),
            fut_c_ev.try_recv().unwrap().unwrap(),
        );

        assert_eq!(val_a_gb, val_a_ev);
        assert_eq!(val_b_gb, val_b_ev);
        assert_eq!(val_c_gb, val_c_ev);
        assert_eq!(val_a_gb, val_a);
        assert_eq!(val_b_gb, val_b);
        assert_eq!(val_c_gb, val_c);
    }

    // Tests that calling decode on a preprocessed output twice behaves
    // correctly.
    #[test]
    fn test_store_decode_preprocessed() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let cot = IdealCOT::new(delta.into_inner());

        let mut gb = GarblerStore::new(rng.random(), delta, cot.clone());
        let mut ev = EvaluatorStore::new(cot);

        let ref_out_gb = gb.alloc_output(16);
        gb.set_output(ref_out_gb, &Key::from_blocks(vec![Block::ZERO; 16]))
            .unwrap();
        std::mem::drop(gb.decode_raw(ref_out_gb).unwrap());

        let ref_out_ev = ev.alloc_output(16);
        ev.mark_output_preprocessed(ref_out_ev).unwrap();
        std::mem::drop(ev.decode_raw(ref_out_ev).unwrap());

        assert!(gb.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gb.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gb.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

        std::mem::drop(gb.decode_raw(ref_out_gb).unwrap());
        std::mem::drop(ev.decode_raw(ref_out_ev).unwrap());

        // There should be nothing to flush, since the decoding info
        // has already been sent in the first flush.
        assert!(!gb.wants_flush() && !ev.wants_flush());
    }
}
