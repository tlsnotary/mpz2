//! An implementation of the Chou-Orlandi [`CO15`](https://eprint.iacr.org/2015/267.pdf) oblivious transfer protocol.

mod error;
pub mod msgs;
mod receiver;
mod sender;

pub use error::{ReceiverError, SenderError, SenderVerifyError};
pub use receiver::{Receiver, state as receiver_state};
pub use sender::{Sender, state as sender_state};

use blake3::Hasher;
use curve25519_dalek::ristretto::RistrettoPoint;
use mpz_core::Block;

/// Hashes a ristretto point to a symmetric key
///
/// Prepending a tweak is suggested in Section 2, "Non-Malleability in Practice"
pub(crate) fn hash_point(point: &RistrettoPoint, tweak: u128) -> Block {
    // Compute H(tweak || point)
    let mut h = Hasher::new();
    h.update(&tweak.to_be_bytes());
    h.update(point.compress().as_bytes());
    let digest = h.finalize();
    let digest: &[u8; 32] = digest.as_bytes();

    // Copy the first 16 bytes into a Block
    let mut block = [0u8; 16];
    block.copy_from_slice(&digest[..16]);
    block.into()
}

#[cfg(test)]
mod tests {
    use crate::{
        ot::{OTReceiver, OTReceiverOutput, OTSender, OTSenderOutput},
        test::assert_ot,
    };

    use super::*;
    use mpz_common::future::Output;
    use rstest::*;

    use rand::RngExt;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    const SENDER_SEED: [u8; 32] = [0u8; 32];
    const RECEIVER_SEED: [u8; 32] = [1u8; 32];

    #[fixture]
    fn choices() -> Vec<bool> {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        (0..128).map(|_| rng.random()).collect()
    }

    #[fixture]
    fn data() -> Vec<[Block; 2]> {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        (0..128)
            .map(|_| {
                [
                    rng.random::<[u8; 16]>().into(),
                    rng.random::<[u8; 16]>().into(),
                ]
            })
            .collect()
    }

    pub(crate) fn setup() -> (Sender<sender_state::Setup>, Receiver<receiver_state::Setup>) {
        let sender = Sender::new_with_seed(SENDER_SEED);
        let receiver = Receiver::new_with_seed(RECEIVER_SEED);

        let (sender_setup, sender) = sender.setup();
        let receiver = receiver.setup(sender_setup);

        (sender, receiver)
    }

    #[rstest]
    fn test_ot_pass(choices: Vec<bool>, data: Vec<[Block; 2]>) {
        let (mut sender, mut receiver) = setup();

        let mut sender_output = sender.queue_send_ot(&data).unwrap();
        let mut receiver_output = receiver.queue_recv_ot(&choices).unwrap();

        let receiver_payload = receiver.choose();
        let sender_payload = sender.send(receiver_payload).unwrap();
        receiver.receive(sender_payload).unwrap();

        let OTSenderOutput { id: sender_id } = sender_output.try_recv().unwrap().unwrap();
        let OTReceiverOutput {
            id: receiver_id,
            msgs,
        } = receiver_output.try_recv().unwrap().unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_ot(&choices, &data, &msgs);
    }

    #[rstest]
    fn test_multiple_ot_pass(choices: Vec<bool>, data: Vec<[Block; 2]>) {
        let (mut sender, mut receiver) = setup();

        let mut sender_output = sender.queue_send_ot(&data).unwrap();
        let mut sender_output2 = sender.queue_send_ot(&data).unwrap();
        let mut receiver_output = receiver.queue_recv_ot(&choices).unwrap();
        let mut receiver_output2 = receiver.queue_recv_ot(&choices).unwrap();

        let receiver_payload = receiver.choose();
        let sender_payload = sender.send(receiver_payload).unwrap();
        receiver.receive(sender_payload).unwrap();

        let OTSenderOutput { id: sender_id } = sender_output.try_recv().unwrap().unwrap();
        let OTReceiverOutput {
            id: receiver_id,
            msgs,
        } = receiver_output.try_recv().unwrap().unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_ot(&choices, &data, &msgs);

        let OTSenderOutput { id: sender_id2 } = sender_output2.try_recv().unwrap().unwrap();
        let OTReceiverOutput {
            id: receiver_id2,
            msgs: msgs2,
        } = receiver_output2.try_recv().unwrap().unwrap();

        assert_eq!(sender_id2, receiver_id2);
        assert_ot(&choices, &data, &msgs2);
    }
}
