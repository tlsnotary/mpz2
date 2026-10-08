mod prover;
mod verifier;

pub use prover::{ProverStore, ProverStoreError};
pub use verifier::{VerifierStore, VerifierStoreError};

use blake3::Hash;
use mpz_core::bitvec::BitVec;
use serde::{Deserialize, Serialize};

use crate::view::FlushView;

#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "validation::ProverFlushUnchecked")]
pub struct ProverFlush {
    view: FlushView,
    adjust: BitVec,
    mac_proof: Option<(BitVec, Hash)>,
}

mod validation {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub(super) struct ProverFlushUnchecked {
        view: FlushView,
        adjust: BitVec,
        mac_proof: Option<(BitVec, Hash)>,
    }

    impl TryFrom<ProverFlushUnchecked> for ProverFlush {
        type Error = String;

        fn try_from(value: ProverFlushUnchecked) -> Result<Self, Self::Error> {
            let ProverFlushUnchecked {
                view,
                adjust,
                mac_proof,
            } = value;

            if view.commit.len() != adjust.len() {
                return Err("prover sent flush with invalid number of adjustment bits".to_string());
            }

            let mac_proof_bits = match mac_proof {
                Some(ref proof) => proof.0.len(),
                None => 0,
            };

            if view.prove.len() != mac_proof_bits {
                return Err("prover sent flush with invalid number of mac proof bits".to_string());
            }

            Ok(ProverFlush {
                view,
                adjust,
                mac_proof,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use blake3::Hasher;
    use mpz_core::bitvec::BitVec;
    use mpz_memory_core::{
        Array, MemoryExt, ViewExt,
        binary::U8,
        correlated::{Delta, Key},
    };
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;

    #[test]
    fn test_store() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let mut prover_transcript = Hasher::default();
        let mut verifier_transcript = Hasher::default();

        let mut verifier = VerifierStore::new(delta);
        let mut prover = ProverStore::new();

        let keys = (0..128).map(|_| rng.random()).collect::<Vec<Key>>();
        let masks = BitVec::from_iter((0..128).map(|_| rng.random::<bool>()));
        let macs = keys
            .iter()
            .zip(&masks)
            .map(|(key, bit)| key.auth(*bit, &delta))
            .collect::<Vec<_>>();

        let a_v: Array<U8, 16> = verifier.alloc().unwrap();
        let b_v: Array<U8, 16> = verifier.alloc().unwrap();

        let a_p: Array<U8, 16> = prover.alloc().unwrap();
        let b_p: Array<U8, 16> = prover.alloc().unwrap();

        verifier.mark_public(a_v).unwrap();
        verifier.mark_blind(b_v).unwrap();
        verifier.assign(a_v, [42u8; 16]).unwrap();
        verifier.commit(a_v).unwrap();
        verifier.commit(b_v).unwrap();

        prover.mark_public(a_p).unwrap();
        prover.mark_private(b_p).unwrap();
        prover.assign(a_p, [42u8; 16]).unwrap();
        prover.assign(b_p, [69u8; 16]).unwrap();
        prover.commit(a_p).unwrap();
        prover.commit(b_p).unwrap();

        let mut b_v = verifier.decode(b_v).unwrap();
        std::mem::drop(prover.decode(b_p).unwrap());

        assert!(verifier.wants_keys());
        assert!(prover.wants_macs());

        assert_eq!(verifier.key_count(), prover.mac_count());

        verifier.set_keys(&keys).unwrap();
        prover.set_macs(&masks, &macs).unwrap();

        // Commit
        assert!(verifier.wants_flush());
        assert!(prover.wants_flush());

        verifier.mark_flush_pending().unwrap();
        let flush_p = prover.send_flush(&mut prover_transcript).unwrap();

        verifier
            .receive_flush(flush_p, &mut verifier_transcript)
            .unwrap();
        prover.complete_flush().unwrap();

        // Prove
        assert!(verifier.wants_flush());
        assert!(prover.wants_flush());

        verifier.mark_flush_pending().unwrap();
        let flush_p = prover.send_flush(&mut prover_transcript).unwrap();

        verifier
            .receive_flush(flush_p, &mut verifier_transcript)
            .unwrap();
        prover.complete_flush().unwrap();

        let b_v = b_v.try_recv().unwrap().unwrap();

        assert_eq!(b_v, [69u8; 16]);
    }
}
