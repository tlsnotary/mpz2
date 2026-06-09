//! An implementation of the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) protocol.

mod config;
pub(crate) mod mpcot;
mod receiver;
mod sender;
pub(crate) mod spcot;

pub use config::{FerretConfig, FerretConfigBuilder, FerretConfigBuilderError, REGULAR_PARAMS};
pub use receiver::{Receiver, ReceiverError};
pub use sender::{Sender, SenderError};

use blake3::Hash;
use mpz_core::Block;
use serde::{Deserialize, Serialize};

use crate::Derandomize;

/// Initialize message sent from receiver to sender.
#[derive(Debug, Serialize, Deserialize)]
pub struct Init {
    seed: Block,
}

/// Extend message sent from sender to receiver.
#[derive(Debug, Serialize, Deserialize)]
pub struct SenderExtend {
    ms: Vec<[Block; 2]>,
    sums: Vec<Block>,
}

/// Check message sent from sender to receiver.
#[derive(Debug, Serialize, Deserialize)]
pub struct SenderCheck {
    hashed_v: Hash,
}

/// Extend message sent from receiver to sender.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiverExtend {
    derandomize: Derandomize,
}

/// Check message sent from receiver to sender.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiverCheck {
    derandomize: Derandomize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ferret::config::TEST_PARAMS,
        ideal::rcot::IdealRCOT,
        rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
        test::assert_cot,
    };
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_ferret() {
        use rand::Rng;

        let mut rng = StdRng::seed_from_u64(0);
        let delta = rng.random();
        let cot = IdealRCOT::new(rng.random(), delta);

        let mut builder = FerretConfig::builder();

        builder.param_selector(|_, _| TEST_PARAMS);

        let config = builder.build().unwrap();
        let count = TEST_PARAMS.n * 2;

        let mut sender = Sender::new(rng.random(), config.clone(), cot.clone());
        let mut receiver = Receiver::new(rng.random(), config, cot);

        assert!(sender.wants_init());
        assert!(receiver.wants_init());

        let init = receiver.initialize().unwrap();
        sender.initialize(init).unwrap();

        assert!(!sender.wants_init());
        assert!(!receiver.wants_init());

        assert!(sender.wants_bootstrap());
        assert!(receiver.wants_bootstrap());

        sender.alloc_bootstrap().unwrap();
        receiver.alloc_bootstrap().unwrap();

        sender.acquire_cot().flush().unwrap();
        receiver.acquire_cot().flush().unwrap();

        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();

        while sender.wants_extend() && receiver.wants_extend() {
            sender.start_extend().unwrap();
            let msg = receiver.start_extend().unwrap();
            let msg = sender.extend(msg).unwrap();
            let msg = receiver.extend(msg).unwrap();
            let msg = sender.check(msg).unwrap();
            receiver.finish_extend(msg).unwrap();
            sender.finish_extend().unwrap();
        }

        assert!(!sender.wants_extend());
        assert!(!receiver.wants_extend());

        let RCOTSenderOutput { keys, .. } = sender.try_send_rcot(count).unwrap();
        let RCOTReceiverOutput { choices, msgs, .. } = receiver.try_recv_rcot(count).unwrap();

        assert_cot(delta, &choices, &keys, &msgs);
    }
}
