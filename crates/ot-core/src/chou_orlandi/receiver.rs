use std::{collections::VecDeque, mem};

use crate::{
    TransferId,
    chou_orlandi::{
        ReceiverError, hash_point,
        msgs::{ReceiverPayload, SenderPayload, SenderSetup},
    },
    ot::{OTReceiver, OTReceiverOutput},
};

use mpz_common::future::{MaybeDone, Sender as OutputSender, new_output};
use mpz_core::Block;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[cfg(feature = "rayon")]
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

type Error = ReceiverError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
struct Queued {
    count: usize,
    sender: OutputSender<OTReceiverOutput<Block>>,
}

/// A [CO15](https://eprint.iacr.org/2015/267.pdf) receiver.
#[derive(Debug, Default)]
pub struct Receiver<T = state::Initialized> {
    queue: VecDeque<Queued>,
    choices: Vec<bool>,
    /// The current state of the protocol
    state: T,
}

impl Receiver {
    /// Creates a new receiver.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            choices: Vec::new(),
            state: state::Initialized::default(),
        }
    }

    /// Creates a new receiver with the provided RNG seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - The RNG seed used to generate the receiver's keys
    pub fn new_with_seed(seed: [u8; 32]) -> Self {
        Self {
            queue: VecDeque::new(),
            choices: Vec::new(),
            state: state::Initialized {
                rng: ChaCha20Rng::from_seed(seed),
            },
        }
    }

    /// Sets up the receiver.
    ///
    /// # Arguments
    ///
    /// * `sender_setup` - The sender's setup message
    pub fn setup(self, sender_setup: SenderSetup) -> Receiver<state::Setup> {
        let state::Initialized { rng } = self.state;

        Receiver {
            queue: self.queue,
            choices: self.choices,
            state: state::Setup {
                rng,
                sender_base_table: RistrettoBasepointTable::create(&sender_setup.public_key),
                transfer_id: TransferId::default(),
                counter: 0,
                decryption_keys: Vec::default(),
            },
        }
    }
}

impl Receiver<state::Setup> {
    /// Returns whether the receiver wants to flush.
    pub fn wants_flush(&self) -> bool {
        !self.choices.is_empty()
    }

    /// Sends the blinded choices to the Sender.
    pub fn choose(&mut self) -> ReceiverPayload {
        let state::Setup {
            rng,
            sender_base_table,
            counter,
            decryption_keys,
            ..
        } = &mut self.state;

        let choices = mem::take(&mut self.choices);
        let private_keys = (0..choices.len())
            .map(|_| Scalar::random(rng))
            .collect::<Vec<_>>();

        let (blinded_choices, new_keys) =
            compute_decryption_keys(sender_base_table, &private_keys, &choices, *counter);

        *counter += blinded_choices.len();
        decryption_keys.extend(new_keys);

        ReceiverPayload { blinded_choices }
    }

    /// Receives the encrypted payload from the Sender.
    ///
    /// # Arguments
    ///
    /// * `payload` - The encrypted payload from the Sender
    pub fn receive(&mut self, payload: SenderPayload) -> Result<()> {
        let state::Setup {
            transfer_id,
            decryption_keys,
            ..
        } = &mut self.state;

        let SenderPayload { payload } = payload;

        // Check that the number of ciphertexts does not exceed the number of
        // pending keys
        if payload.len() != decryption_keys.len() {
            return Err(ReceiverError::CountMismatch(
                decryption_keys.len(),
                payload.len(),
            ));
        }

        let mut msgs =
            decryption_keys
                .drain(..payload.len())
                .zip(payload)
                .map(
                    |((c, key), [ct0, ct1])| {
                        if c { key ^ ct1 } else { key ^ ct0 }
                    },
                );

        while let Some(Queued { count, sender }) = self.queue.pop_front() {
            let output = OTReceiverOutput {
                id: transfer_id.next(),
                msgs: msgs.by_ref().take(count).collect(),
            };

            sender.send(output);
        }

        Ok(())
    }
}

impl<T> OTReceiver<bool, Block> for Receiver<T>
where
    T: state::State,
{
    type Error = Error;
    type Future = MaybeDone<OTReceiverOutput<Block>>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn queue_recv_ot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        self.choices.extend(choices);
        self.queue.push_back(Queued {
            count: choices.len(),
            sender,
        });

        Ok(recv)
    }
}

/// Computes the blinded choices `B` and the decryption keys for the OT
/// receiver.
///
/// # Arguments
///
/// * `base_table` - A Ristretto basepoint table from the sender's public key
/// * `receiver_private_keys` - The private keys of the OT receiver
/// * `choices` - The choices of the OT receiver
/// * `offset` - The number of decryption keys that have already been computed
///   (used for the key derivation tweak)
fn compute_decryption_keys(
    base_table: &RistrettoBasepointTable,
    receiver_private_keys: &[Scalar],
    choices: &[bool],
    offset: usize,
) -> (Vec<RistrettoPoint>, Vec<(bool, Block)>) {
    let zero = &Scalar::ZERO * base_table;
    // a is A in [ref1]
    let a = &Scalar::ONE * base_table;

    cfg_if::cfg_if! {
        if #[cfg(feature = "rayon")] {
            let iter = receiver_private_keys.into_par_iter().zip(choices.into_par_iter().copied()).enumerate();
        } else {
            let iter = receiver_private_keys.iter().zip(choices.iter().copied()).enumerate();
        }
    }

    iter.map(|(i, (b, c))| {
        // blinded_choice is B in [ref1]
        //
        // if c = 0: B = g ^ b
        // if c = 1: B = A * g ^ b
        //
        // when choice is 0, we add the zero element to keep constant time.
        let blinded_choice = if c {
            a + b * RISTRETTO_BASEPOINT_TABLE
        } else {
            zero + b * RISTRETTO_BASEPOINT_TABLE
        };

        let decryption_key = hash_point(&(b * base_table), (offset + i) as u128);

        (blinded_choice, (c, decryption_key))
    })
    .unzip()
}

/// The receiver's state.
pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Setup {}
    }

    /// The receiver's state.
    pub trait State: sealed::Sealed {}

    /// The receiver's initial state.
    pub struct Initialized {
        /// RNG used to generate the receiver's keys
        pub(super) rng: ChaCha20Rng,
    }

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    impl Default for Initialized {
        fn default() -> Self {
            Self {
                rng: ChaCha20Rng::from_rng(&mut rand::rng()),
            }
        }
    }

    /// The receiver's state after setup.
    pub struct Setup {
        /// RNG used to generate the receiver's keys
        pub(super) rng: ChaCha20Rng,
        /// Sender's public key (precomputed table)
        pub(super) sender_base_table: RistrettoBasepointTable,
        /// Current transfer id.
        pub(super) transfer_id: TransferId,
        /// Counts how many decryption keys we've computed so far
        pub(super) counter: usize,

        /// The decryption key for each OT, with the corresponding choice bit
        pub(super) decryption_keys: Vec<(bool, Block)>,
    }

    impl State for Setup {}

    opaque_debug::implement!(Setup);
}

#[cfg(test)]
mod tests {
    use crate::{
        chou_orlandi::{ReceiverError, msgs::SenderPayload, tests::setup},
        ot::OTReceiver,
    };
    use mpz_core::Block;

    #[test]
    fn test_receive_count_err() {
        let (_, mut receiver) = setup();

        _ = receiver.queue_recv_ot(&[true, false]).unwrap();

        matches!(
            receiver.receive(SenderPayload {
                payload: vec![[Block::ZERO; 2]],
            }),
            Err(ReceiverError::CountMismatch(2, 1))
        );

        matches!(
            receiver.receive(SenderPayload {
                payload: vec![[Block::ZERO; 2]; 3],
            }),
            Err(ReceiverError::CountMismatch(2, 3))
        );
    }
}
