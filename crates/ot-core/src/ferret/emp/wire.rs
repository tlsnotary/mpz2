//! Adapters that re-frame the sans-IO Ferret messages as emp-ot's raw wire
//! bytes, for cross-implementation comparison.
//!
//! emp-ot streams per tree with no framing and its receiver sends nothing,
//! so only the extend messages map:
//!
//! | Rust message     | emp wire                                    |
//! |------------------|---------------------------------------------|
//! | `SenderExtend`   | per-tree cGGM corrections, concatenated     |
//! | `ReceiverExtend` | nothing - emp derives the derandomization   |
//!
//! The check messages are not rendered: their values differ by construction
//! (the challenge seed is sampled by the verifier here). The coin-toss fields
//! (`lpn_seed_*`) likewise have no emp counterpart.

use crate::ferret::{ReceiverExtend, SenderExtend};
use mpz_core::Block;

fn concat_blocks(blocks: &[Block]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blocks.len() * 16);
    for block in blocks {
        out.extend_from_slice(block.as_bytes());
    }
    out
}

/// Sender extend -> emp's sender→receiver stream: the concatenation of the
/// per-tree `c` (one `tree_depth`-block correction per tree). emp sends
/// each tree's `c` separately; the bytes are the same concatenated.
pub(crate) fn sender_extend(msg: &SenderExtend) -> Vec<u8> {
    concat_blocks(&msg.cs)
}

/// Receiver extend -> emp's receiver→sender stream: empty. emp sends
/// nothing here; it derives the derandomization from its base COTs.
pub(crate) fn receiver_extend(_msg: &ReceiverExtend) -> Vec<u8> {
    Vec::new()
}
