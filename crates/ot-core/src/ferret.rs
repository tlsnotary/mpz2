//! An implementation of the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) protocol,
//! using the [`Half-Tree`](https://eprint.iacr.org/2022/1431) correlated GGM
//! optimization.
//!
//! The [emp-toolkit](https://github.com/emp-toolkit/emp-ot) implementation was
//! used as a reference, in particular for the correlated GGM tree construction
//! and its composition with the consistency check.

mod config;
#[cfg(feature = "emp")]
mod emp;
mod mpcot;
mod receiver;
mod sender;
mod spcot;
#[cfg(test)]
mod tests;

pub use config::{FerretConfig, FerretConfigBuilder, FerretConfigBuilderError, REGULAR_PARAMS};
pub use receiver::{Receiver, ReceiverError};
pub use sender::{Sender, SenderError};

use blake3::Hash;
use mpz_cointoss_core::msgs as cointoss_msgs;
use mpz_core::Block;
use mpz_fields::gf2_128::Gf2_128;
use serde::{Deserialize, Serialize};

use crate::Derandomize;

/// Splits the last `count` correlations off the buffer, converting them to
/// blocks for the RCOT interface.
fn split_off_blocks(buffer: &mut Vec<Gf2_128>, count: usize) -> Vec<Block> {
    let start = buffer.len() - count;
    let blocks = buffer[start..].iter().map(|&x| Block::from(x)).collect();
    buffer.truncate(start);

    blocks
}

/// Extend message sent from sender to receiver.
#[derive(Debug, Serialize, Deserialize)]
pub struct SenderExtend {
    cs: Vec<Block>,
    /// The sender's contribution to the LPN seed coin-toss.
    lpn_seed_share: cointoss_msgs::ReceiverPayload,
}

/// Check message sent from sender to receiver.
#[derive(Debug, Serialize, Deserialize)]
pub struct SenderCheck {
    hashed_v: Hash,
}

/// Extend message sent from receiver to sender.
///
/// The LPN seed for each extension is agreed with a coin-toss piggybacked on
/// the extension messages, so that neither party can bias the seed towards a
/// weak LPN code. The receiver plays the coin-toss sender: it commits here,
/// and decommits in [`ReceiverCheck`] after the sender has contributed its
/// share.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiverExtend {
    derandomize: Derandomize,
    /// Commitment to the receiver's contribution to the LPN seed coin-toss.
    lpn_seed_commitment: cointoss_msgs::SenderCommitment,
}

/// Check message sent from receiver to sender.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiverCheck {
    derandomize: Derandomize,
    /// Seed for the consistency check's random linear combination.
    chi_seed: Block,
    /// Decommitment to the receiver's contribution to the LPN seed
    /// coin-toss.
    lpn_seed_decommitment: cointoss_msgs::SenderPayload,
}
