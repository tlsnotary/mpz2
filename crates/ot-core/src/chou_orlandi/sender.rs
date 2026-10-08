use std::{collections::VecDeque, mem};

use crate::{
    TransferId,
    chou_orlandi::{
        SenderError, hash_point,
        msgs::{ReceiverPayload, SenderPayload, SenderSetup},
    },
    ot::{OTSender, OTSenderOutput},
};

use mpz_common::future::{MaybeDone, Sender as OutputSender, new_output};
use mpz_core::Block;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[cfg(feature = "rayon")]
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

type Error = SenderError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
struct Queued {
    sender: OutputSender<OTSenderOutput>,
}

/// A [CO15](https://eprint.iacr.org/2015/267.pdf) sender.
#[derive(Debug, Default)]
pub struct Sender<T: state::State = state::Initialized> {
    queue: VecDeque<Queued>,
    msgs: Vec<[Block; 2]>,
    /// Current state
    state: T,
}

impl Sender {
    /// Creates a new Sender
    pub fn new() -> Self {
        Sender {
            queue: VecDeque::new(),
            msgs: Vec::new(),
            state: state::Initialized::default(),
        }
    }

    /// Creates a new Sender with the provided RNG seed
    ///
    /// # Arguments
    /// * `seed` - The RNG seed used to generate the sender's keys
    pub fn new_with_seed(seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);

        let private_key = Scalar::random(&mut rng);
        let public_key = &private_key * RISTRETTO_BASEPOINT_TABLE;
        let state = state::Initialized {
            private_key,
            public_key,
        };

        Sender {
            queue: VecDeque::new(),
            msgs: Vec::new(),
            state,
        }
    }

    /// Returns the setup message to be sent to the receiver.
    pub fn setup(self) -> (SenderSetup, Sender<state::Setup>) {
        let state::Initialized {
            private_key,
            public_key,
        } = self.state;

        (
            SenderSetup { public_key },
            Sender {
                queue: self.queue,
                msgs: self.msgs,
                state: state::Setup {
                    private_key,
                    public_key,
                    transfer_id: TransferId::default(),
                    counter: 0,
                },
            },
        )
    }
}

impl Sender<state::Setup> {
    /// Returns `true` if the sender wants to receive.
    pub fn wants_recv(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Obliviously sends messages to the receiver.
    ///
    /// # Arguments
    ///
    /// * `receiver_payload` - The receiver's choice payload.
    pub fn send(&mut self, receiver_payload: ReceiverPayload) -> Result<SenderPayload> {
        let state::Setup {
            private_key,
            public_key,
            transfer_id,
            counter,
            ..
        } = &mut self.state;

        let ReceiverPayload { blinded_choices } = receiver_payload;
        let msgs = mem::take(&mut self.msgs);

        // Check that the number of messages matches the number of choices
        if msgs.len() != blinded_choices.len() {
            return Err(SenderError::CountMismatch(
                msgs.len(),
                blinded_choices.len(),
            ));
        }

        let mut payload =
            compute_encryption_keys(private_key, public_key, &blinded_choices, *counter);

        *counter += msgs.len();

        // Encrypt the messages
        for (msg, payload) in msgs.iter().zip(payload.iter_mut()) {
            payload[0] = msg[0] ^ payload[0];
            payload[1] = msg[1] ^ payload[1];
        }

        // Clear the queue.
        for Queued { sender } in self.queue.drain(..) {
            sender.send(OTSenderOutput {
                id: transfer_id.next(),
            });
        }

        Ok(SenderPayload { payload })
    }
}

impl<S> OTSender<Block> for Sender<S>
where
    S: state::State,
{
    type Error = Error;
    type Future = MaybeDone<OTSenderOutput>;

    fn alloc(&mut self, _count: usize) -> Result<()> {
        Ok(())
    }

    fn queue_send_ot(&mut self, msgs: &[[Block; 2]]) -> Result<Self::Future> {
        let (sender, recv) = new_output();

        self.msgs.extend_from_slice(msgs);
        self.queue.push_back(Queued { sender });

        Ok(recv)
    }
}

/// Computes the encryption keys for the sender.
///
/// # Arguments
///
/// * `private_key` - The sender's private key.
/// * `public_key` - The sender's public key.
/// * `blinded_choices` - The receiver's blinded choices.
/// * `offset` - The number of OTs that have already been performed (used for
///   the key derivation tweak)
fn compute_encryption_keys(
    private_key: &Scalar,
    public_key: &RistrettoPoint,
    blinded_choices: &[RistrettoPoint],
    offset: usize,
) -> Vec<[Block; 2]> {
    // ys is A^a in [ref1]
    let ys = private_key * public_key;

    cfg_if::cfg_if! {
        if #[cfg(feature = "rayon")] {
            let iter = blinded_choices
                .par_iter()
                .enumerate();
        } else {
            let iter = blinded_choices
                .iter()
                .enumerate();
        }
    }

    iter.map(|(i, blinded_choice)| {
        // yr is B^a in [ref1]
        let yr = private_key * blinded_choice;
        let k0 = hash_point(&yr, (offset + i) as u128);
        // yr - ys == (B/A)^a in [ref1]
        let k1 = hash_point(&(yr - ys), (offset + i) as u128);

        [k0, k1]
    })
    .collect()
}

/// The sender's state.
pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Setup {}
    }

    /// The sender's state.
    pub trait State: sealed::Sealed {}

    /// The sender's initial state.
    pub struct Initialized {
        /// The private_key is random `a` in [ref1]
        pub(super) private_key: Scalar,
        // The public_key is `A == g^a` in [ref1]
        pub(super) public_key: RistrettoPoint,
    }

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    impl Default for Initialized {
        fn default() -> Self {
            let mut rng = ChaCha20Rng::from_rng(&mut rand::rng());
            let private_key = Scalar::random(&mut rng);
            let public_key = &private_key * RISTRETTO_BASEPOINT_TABLE;
            Initialized {
                private_key,
                public_key,
            }
        }
    }

    /// The sender's state when setup is complete.
    pub struct Setup {
        /// The private_key is random `a` in [ref1]
        pub(super) private_key: Scalar,
        // The public_key is `A == g^a` in [ref1]
        pub(super) public_key: RistrettoPoint,
        /// Current transfer id.
        pub(super) transfer_id: TransferId,
        /// Number of OTs sent so far
        pub(super) counter: usize,
    }

    impl State for Setup {}

    opaque_debug::implement!(Setup);
}
