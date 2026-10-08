//! Secure two-party (2PC) multiplication-to-addition (M2A) and
//! addition-to-multiplication (A2M) algorithms, both with semi-honest security.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![deny(unsafe_code)]

pub(crate) mod a2m;
#[cfg(any(test, feature = "test-utils"))]
pub mod ideal;
mod receiver;
mod sender;

pub use receiver::{Receiver, ReceiverError};
pub use sender::{Sender, SenderError};

use a2m::A2MMasked;
use mpz_common::future::Output;
use mpz_ole_core::Offset;
use serde::{Deserialize, Serialize};

/// Output of A2M conversion.
#[derive(Debug)]
pub struct A2MOutput<F> {
    /// Multiplicative shares.
    pub shares: Vec<F>,
}

/// Additive to multiplicative share conversion.
pub trait AdditiveToMultiplicative<F> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<A2MOutput<F>>;

    /// Allocates `count` A2M for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Queues additive to multiplicative conversion.
    fn queue_to_multiplicative(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error>;
}

/// Output of M2A conversion.
#[derive(Debug)]
pub struct M2AOutput<F> {
    /// Additive shares.
    pub shares: Vec<F>,
}

/// Multiplicative to additive share conversion.
pub trait MultiplicativeToAdditive<F> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<M2AOutput<F>>;

    /// Allocates `count` M2A for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Queues multiplicative to additive conversion.
    fn queue_to_additive(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error>;
}

/// Share conversion.
pub trait ShareConvert<F>:
    AdditiveToMultiplicative<F>
    + MultiplicativeToAdditive<F, Error = <Self as AdditiveToMultiplicative<F>>::Error>
{
}

impl<F, T> ShareConvert<F> for T where
    T: AdditiveToMultiplicative<F>
        + MultiplicativeToAdditive<F, Error = <Self as AdditiveToMultiplicative<F>>::Error>
{
}

/// Sender message for A2M conversion.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendA2M<F> {
    masked_shares: Vec<A2MMasked<F>>,
}

/// Sender message for M2A conversion.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendM2A<F> {
    offsets: Vec<Offset<F>>,
}

/// Receiver message for A2M conversion.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecvA2M<F> {
    offsets: Vec<Offset<F>>,
}

/// Receiver message for M2A conversion.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecvM2A<F> {
    offsets: Vec<Offset<F>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_fields::{Field, gf2_128::Gf2_128, p256::P256};
    use mpz_ole_core::ideal::IdealROLE;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    #[test]
    fn test_a2m_p256() {
        test_a2m::<P256>();
    }

    #[test]
    fn test_a2m_gf2_128() {
        test_a2m::<Gf2_128>();
    }

    fn test_a2m<F: Field>() {
        let mut rng = StdRng::seed_from_u64(0);

        let ideal_role = IdealROLE::<F>::new(rng.random());

        let sender_input = F::rand(&mut rng);
        let receiver_input = F::rand(&mut rng);
        let secret = sender_input + receiver_input;

        let mut sender = Sender::<_, F>::new(ideal_role.clone());
        let mut receiver = Receiver::<_, F>::new(ideal_role);

        AdditiveToMultiplicative::alloc(&mut sender, 1).unwrap();
        AdditiveToMultiplicative::alloc(&mut receiver, 1).unwrap();

        sender.role_mut().flush().unwrap();

        let mut sender_output = sender.queue_to_multiplicative(&[sender_input]).unwrap();
        let mut receiver_output = receiver.queue_to_multiplicative(&[receiver_input]).unwrap();

        assert!(sender.wants_a2m());
        assert!(receiver.wants_a2m());

        let msg = receiver.send_a2m().unwrap();
        sender.recv_a2m(msg).unwrap();

        assert!(!sender.wants_a2m());
        assert!(!receiver.wants_a2m());

        let msg = sender.send_a2m().unwrap();
        receiver.recv_a2m(msg).unwrap();

        assert!(!sender.wants_a2m());
        assert!(!receiver.wants_a2m());

        let A2MOutput {
            shares: sender_shares,
        } = sender_output.try_recv().unwrap().unwrap();
        let A2MOutput {
            shares: receiver_shares,
        } = receiver_output.try_recv().unwrap().unwrap();

        assert_eq!(sender_shares[0] * receiver_shares[0], secret);
    }

    #[test]
    fn test_m2a_p256() {
        test_m2a::<P256>();
    }

    #[test]
    fn test_m2a_gf2_128() {
        test_m2a::<Gf2_128>();
    }

    fn test_m2a<F: Field>() {
        let mut rng = StdRng::seed_from_u64(0);

        let ideal_role = IdealROLE::<F>::new(rng.random());

        let sender_input = F::rand(&mut rng);
        let receiver_input = F::rand(&mut rng);
        let secret = sender_input * receiver_input;

        let mut sender = Sender::<_, F>::new(ideal_role.clone());
        let mut receiver = Receiver::<_, F>::new(ideal_role);

        MultiplicativeToAdditive::alloc(&mut sender, 1).unwrap();
        MultiplicativeToAdditive::alloc(&mut receiver, 1).unwrap();

        sender.role_mut().flush().unwrap();

        let mut sender_output = sender.queue_to_additive(&[sender_input]).unwrap();
        let mut receiver_output = receiver.queue_to_additive(&[receiver_input]).unwrap();

        assert!(sender.wants_m2a());
        assert!(receiver.wants_m2a());

        let sender_msg = sender.send_m2a().unwrap();
        let receiver_msg = receiver.send_m2a().unwrap();

        sender.recv_m2a(receiver_msg).unwrap();
        receiver.recv_m2a(sender_msg).unwrap();

        assert!(!sender.wants_m2a());
        assert!(!receiver.wants_m2a());

        let M2AOutput {
            shares: sender_shares,
        } = sender_output.try_recv().unwrap().unwrap();
        let M2AOutput {
            shares: receiver_shares,
        } = receiver_output.try_recv().unwrap().unwrap();

        assert_eq!(sender_shares[0] + receiver_shares[0], secret);
    }
}
