//! A simple 2-party coin-toss protocol.
//!
//! # Example
//!
//! ```
//! use mpz_cointoss_core::{Sender, Receiver, CointossError};
//! use mpz_core::Block;
//!
//! # fn main() -> Result<(), CointossError> {
//! let sender_seeds = (0..8).map(|_| Block::random(&mut rand::rng())).collect();
//! let receiver_seeds = (0..8).map(|_| Block::random(&mut rand::rng())).collect();
//!
//! let sender = Sender::new(sender_seeds);
//! let receiver = Receiver::new(receiver_seeds);
//!
//! let (sender, commitment) = sender.send();
//! let (receiver, receiver_payload) = receiver.reveal(commitment)?;
//! let (sender_output, sender) = sender.receive(receiver_payload)?;
//! let sender_payload = sender.finalize();
//! let receiver_output = receiver.finalize(sender_payload)?;
//!
//! assert_eq!(sender_output, receiver_output);
//! # Ok(())
//! # }
//! ```

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

pub mod msgs;
mod receiver;
mod sender;

pub use receiver::{Receiver, receiver_state};
pub use sender::{Sender, sender_state};

/// A coin-toss error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum CointossError {
    #[error("commitment error")]
    CommitmentError(#[from] mpz_core::commit::CommitmentError),
    #[error("count mismatch, expected {expected}, got {actual}")]
    CountMismatch { expected: usize, actual: usize },
}
