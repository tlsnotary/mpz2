//! Correlated random oblivious transfer extension protocol with leakage based
//! on [`KOS15`](https://eprint.iacr.org/archive/2015/546/1433798896.pdf).
//!
//! # Warning
//!
//! The user of this protocol must carefully consider if the leakage introduced
//! in this protocol is acceptable for their specific application.

mod receiver;
mod sender;

pub use receiver::Receiver;
pub use sender::Sender;

pub use mpz_ot_core::kos::{
    ReceiverConfig, ReceiverConfigBuilder, ReceiverConfigBuilderError, SenderConfig,
    SenderConfigBuilder, SenderConfigBuilderError, msgs,
};

#[cfg(test)]
mod tests {
    use mpz_core::Block;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    use crate::{ideal::ot::ideal_ot, test::test_rcot};

    #[tokio::test]
    async fn test_kos_rcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let (base_sender, base_receiver) = ideal_ot();
        let delta = Block::random(&mut rng);
        let sender = Sender::new(SenderConfig::default(), delta, Block::ZERO, base_receiver);
        let receiver = Receiver::new(ReceiverConfig::default(), Block::ZERO, base_sender);

        test_rcot(sender, receiver, 128, 1).await;
    }
}
