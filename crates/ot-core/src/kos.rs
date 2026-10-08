//! Correlated random oblivious transfer extension protocol with leakage based
//! on [`KOS15`](https://eprint.iacr.org/2015/546).
//!
//! # Warning
//!
//! The user of this protocol must carefully consider if the leakage introduced
//! in this protocol is acceptable for their specific application.

mod config;
mod error;
pub mod msgs;
mod receiver;
mod sender;

pub use config::{
    ReceiverConfig, ReceiverConfigBuilder, ReceiverConfigBuilderError, SenderConfig,
    SenderConfigBuilder, SenderConfigBuilderError,
};
pub use error::{ReceiverError, SenderError};
use mpz_core::Block;
pub use receiver::{Receiver, state as receiver_state};
pub use sender::{Sender, state as sender_state};
use serde::{Deserialize, Serialize};

/// Computational security parameter
pub const CSP: usize = 128;
/// Statistical security parameter
pub const SSP: usize = 128;

/// Returns the size in bytes of the extension matrix for a given number of OTs.
fn extension_matrix_size(count: usize) -> usize {
    count * CSP / 8
}

/// Extend message sent from Receiver to Sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "validation::ExtendUnchecked")]
pub struct Extend {
    count: usize,
    us: Vec<u8>,
}

/// Check message sent from Receiver to Sender.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "validation::CheckUnchecked")]
pub struct Check {
    x: Block,
    t: Vec<Block>,
}

mod validation {
    use super::*;

    #[derive(Deserialize)]
    pub(super) struct ExtendUnchecked {
        count: usize,
        us: Vec<u8>,
    }

    impl TryFrom<ExtendUnchecked> for Extend {
        type Error = String;

        fn try_from(value: ExtendUnchecked) -> Result<Self, Self::Error> {
            let ExtendUnchecked { count, us } = value;

            if us.len() != extension_matrix_size(count) {
                return Err("invalid extension matrix size".to_string());
            }

            Ok(Extend { count, us })
        }
    }

    #[derive(Deserialize)]
    pub(super) struct CheckUnchecked {
        x: Block,
        t: Vec<Block>,
    }

    impl TryFrom<CheckUnchecked> for Check {
        type Error = String;

        fn try_from(value: CheckUnchecked) -> Result<Self, Self::Error> {
            let CheckUnchecked { x, t } = value;

            if t.len() != CSP {
                return Err("t length is invalid".to_string());
            }

            Ok(Check { x, t })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
        test::assert_cot,
    };

    use super::*;
    use itybity::ToBits;
    use rstest::*;

    use mpz_core::Block;

    use rand::RngExt;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    #[fixture]
    fn choices() -> Vec<bool> {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        (0..128).map(|_| rng.random()).collect()
    }

    #[fixture]
    fn data() -> Vec<[Block; 2]> {
        let mut rng = ChaCha12Rng::seed_from_u64(1);
        (0..128)
            .map(|_| {
                [
                    rng.random::<[u8; 16]>().into(),
                    rng.random::<[u8; 16]>().into(),
                ]
            })
            .collect()
    }

    #[fixture]
    fn delta() -> Block {
        let mut rng = ChaCha12Rng::seed_from_u64(2);
        rng.random::<[u8; 16]>().into()
    }

    #[fixture]
    fn receiver_seeds() -> [[Block; 2]; CSP] {
        let mut rng = ChaCha12Rng::seed_from_u64(3);
        std::array::from_fn(|_| [rng.random(), rng.random()])
    }

    #[fixture]
    fn sender_seeds(delta: Block, receiver_seeds: [[Block; 2]; CSP]) -> [Block; CSP] {
        delta
            .iter_lsb0()
            .zip(receiver_seeds)
            .map(|(b, seeds)| if b { seeds[1] } else { seeds[0] })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[fixture]
    fn chi_seed() -> Block {
        let mut rng = ChaCha12Rng::seed_from_u64(4);
        rng.random::<[u8; 16]>().into()
    }

    #[fixture]
    fn expected(data: Vec<[Block; 2]>, choices: Vec<bool>) -> Vec<Block> {
        data.iter()
            .zip(choices.iter())
            .map(|([a, b], choice)| if *choice { *b } else { *a })
            .collect()
    }

    #[rstest]
    fn test_kos_extension(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
    ) {
        let count = 128;

        let sender = Sender::new(SenderConfig::default(), delta);
        let receiver = Receiver::new(ReceiverConfig::default());

        let mut sender = sender.setup(sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();

        assert!(sender.wants_extend());
        assert!(receiver.wants_extend());

        while receiver.wants_extend() {
            sender.extend(receiver.extend().unwrap()).unwrap();
        }

        assert!(!sender.wants_extend());
        assert!(!receiver.wants_extend());
        assert!(sender.wants_check());
        assert!(receiver.wants_check());

        let chi_seed = sender.check_start();
        let receiver_check = receiver.check(chi_seed).unwrap();
        sender.check(receiver_check).unwrap();

        assert_eq!(sender.available(), count);
        assert_eq!(receiver.available(), count);

        let RCOTSenderOutput {
            id: sender_id,
            keys,
        } = sender.try_send_rcot(count).unwrap();
        let RCOTReceiverOutput {
            id: receiver_id,
            choices,
            msgs,
        } = receiver.try_recv_rcot(count).unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_cot(delta, &choices, &keys, &msgs);
    }

    #[rstest]
    fn test_kos_extension_stream_extends(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
    ) {
        let sender_config = SenderConfig::default();
        let receiver_config = ReceiverConfig::default();

        let count = sender_config.batch_size() * 3;

        let sender = Sender::new(sender_config, delta);
        let receiver = Receiver::new(receiver_config);

        let mut sender = sender.setup(sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();

        assert!(sender.wants_extend());
        assert!(receiver.wants_extend());

        while receiver.wants_extend() {
            sender.extend(receiver.extend().unwrap()).unwrap();
        }

        assert!(!sender.wants_extend());
        assert!(!receiver.wants_extend());
        assert!(sender.wants_check());
        assert!(receiver.wants_check());

        let chi_seed = sender.check_start();
        let receiver_check = receiver.check(chi_seed).unwrap();
        sender.check(receiver_check).unwrap();

        assert_eq!(sender.available(), count);
        assert_eq!(receiver.available(), count);

        let RCOTSenderOutput {
            id: sender_id,
            keys,
        } = sender.try_send_rcot(count).unwrap();
        let RCOTReceiverOutput {
            id: receiver_id,
            choices,
            msgs,
        } = receiver.try_recv_rcot(count).unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_cot(delta, &choices, &keys, &msgs);
    }

    #[rstest]
    fn test_kos_extension_multiple_extends_fail(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
    ) {
        let count = 128;

        let sender = Sender::new(SenderConfig::default(), delta);
        let receiver = Receiver::new(ReceiverConfig::default());

        let mut sender = sender.setup(sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();

        while receiver.wants_extend() {
            sender.extend(receiver.extend().unwrap()).unwrap();
        }

        let chi_seed = sender.check_start();
        let receiver_check = receiver.check(chi_seed).unwrap();
        sender.check(receiver_check).unwrap();

        assert!(sender.alloc(1).is_err());
        assert!(receiver.alloc(1).is_err());
        assert!(!sender.wants_extend());
        assert!(!receiver.wants_extend());
        assert!(receiver.extend().is_err());
    }

    #[rstest]
    fn test_kos_extension_insufficient_setup(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
    ) {
        let count = 128;

        let sender = Sender::new(SenderConfig::default(), delta);
        let receiver = Receiver::new(ReceiverConfig::default());

        let mut sender = sender.setup(sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();

        while receiver.wants_extend() {
            sender.extend(receiver.extend().unwrap()).unwrap();
        }

        let chi_seed = sender.check_start();
        let receiver_check = receiver.check(chi_seed).unwrap();
        sender.check(receiver_check).unwrap();

        let err = sender.try_send_rcot(count + 1).unwrap_err();
        assert!(matches!(err, SenderError::InsufficientSetup { .. }));

        let err = receiver.try_recv_rcot(count + 1).unwrap_err();
        assert!(matches!(err, ReceiverError::InsufficientSetup { .. }));
    }

    #[rstest]
    fn test_kos_extension_bad_consistency_check(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
    ) {
        let count = 128;

        let sender = Sender::new(SenderConfig::default(), delta);
        let receiver = Receiver::new(ReceiverConfig::default());

        let mut sender = sender.setup(sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();

        while receiver.wants_extend() {
            let mut extend = receiver.extend().unwrap();

            // Flip a bit in the receiver's extension message (breaking the
            // mono-chrome choice vector)
            *extend.us.first_mut().unwrap() ^= 1;

            sender.extend(extend).unwrap();
        }

        let chi_seed = sender.check_start();
        let receiver_check = receiver.check(chi_seed).unwrap();
        let err = sender.check(receiver_check).unwrap_err();

        assert!(matches!(err, SenderError::ConsistencyCheckFailed));
    }
}
