//! Core types and utilities for MPC protocols
#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]

pub mod aes;
pub mod bitvec;
pub mod block;
pub mod cggm;
pub mod commit;
pub mod hash;
pub mod lpn;
pub mod prg;
pub mod prp;
pub mod rand;
pub mod serialize;
pub mod utils;

pub use block::{Block, BlockSerialize};

/// A protocol with a message type.
pub trait ProtocolMessage {
    /// The type of message used in the protocol.
    type Msg: Send + Sync + std::fmt::Debug + 'static;
}
