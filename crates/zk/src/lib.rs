mod callstack;
mod config;
mod prover;
mod verifier;

pub use config::{ProverConfig, VerifierConfig};
pub use prover::Prover;
pub use verifier::Verifier;

#[cfg(test)]
mod tests {
    use mpz_circuits::AES128;
    use mpz_common::context::test_st_context;
    use mpz_ot::ideal::rcot::{IdealRCOTReceiver, IdealRCOTSender, ideal_rcot};
    use mpz_vm_core::{
        Call, Vm,
        memory::{
            Array,
            binary::{Binary, U8},
            correlated::Delta,
        },
        prelude::*,
    };
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;

    #[test]
    fn test_zk_is_vm() {
        fn is_vm<T: Vm<Binary>>() {}
        is_vm::<Prover<IdealRCOTReceiver>>();
        is_vm::<Verifier<IdealRCOTSender>>();
    }

    #[tokio::test]
    async fn test_zk() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let (mut ctx_p, mut ctx_v) = test_st_context(8);

        let (ot_send, ot_recv) = ideal_rcot(rng.random(), delta.into_inner());

        let mut prover = Prover::new(ProverConfig::default(), ot_recv);
        let mut verifier = Verifier::new(VerifierConfig::default(), delta, ot_send);

        let (ciphertext_p, ciphertext_v) = futures::join!(
            {
                let key: Array<U8, 16> = prover.alloc().unwrap();
                let msg: Array<U8, 16> = prover.alloc().unwrap();

                let ciphertext: Array<U8, 16> = prover
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                prover.mark_private(key).unwrap();
                prover.mark_public(msg).unwrap();

                prover.assign(key, [0u8; 16]).unwrap();
                prover.assign(msg, [42u8; 16]).unwrap();

                prover.commit(key).unwrap();
                prover.commit(msg).unwrap();

                let mut ciphertext = prover.decode(ciphertext).unwrap();

                async move {
                    prover.execute_all(&mut ctx_p).await.unwrap();
                    ciphertext.try_recv().unwrap().unwrap()
                }
            },
            {
                let key: Array<U8, 16> = verifier.alloc().unwrap();
                let msg: Array<U8, 16> = verifier.alloc().unwrap();

                let ciphertext: Array<U8, 16> = verifier
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                verifier.mark_blind(key).unwrap();
                verifier.mark_public(msg).unwrap();

                verifier.assign(msg, [42u8; 16]).unwrap();

                verifier.commit(key).unwrap();
                verifier.commit(msg).unwrap();

                let mut ciphertext = verifier.decode(ciphertext).unwrap();

                async move {
                    verifier.execute_all(&mut ctx_v).await.unwrap();
                    ciphertext.try_recv().unwrap().unwrap()
                }
            }
        );

        assert_eq!(ciphertext_p, ciphertext_v);
    }
}
