//! Adapter to convert an RCOT protocol to ROT.

mod receiver;
mod sender;

pub use receiver::RandomizeRCOTReceiver;
pub use sender::RandomizeRCOTSender;

#[cfg(test)]
mod tests {
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use crate::{ideal::rcot::ideal_rcot, test::test_rot};

    use super::*;

    #[tokio::test]
    async fn test_randomize_rcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let (sender, receiver) = ideal_rcot(rng.random(), rng.random());
        test_rot(
            RandomizeRCOTSender::new(sender),
            RandomizeRCOTReceiver::new(receiver),
            8,
        )
        .await
    }
}
