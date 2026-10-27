//! An implementation of the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) protocol,
//! using the [`Half-Tree`](https://eprint.iacr.org/2022/1431) correlated GGM
//! optimization.
//!
//! The [emp-toolkit](https://github.com/emp-toolkit/emp-ot) implementation was
//! used as a reference, in particular for the correlated GGM tree construction
//! and its composition with the consistency check.

mod config;
mod mpcot;
mod receiver;
mod sender;
mod spcot;

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

/// Adapters that re-frame the sans-IO Ferret messages as emp-ot's raw wire
/// bytes, for cross-implementation comparison.
///
/// emp-ot streams per tree with no framing and its receiver sends nothing,
/// so only the extend messages map:
///
/// | Rust message     | emp wire                                    |
/// |------------------|---------------------------------------------|
/// | `SenderExtend`   | per-tree cGGM corrections, concatenated     |
/// | `ReceiverExtend` | nothing - emp derives the derandomization   |
///
/// The check messages are not rendered: their values differ by construction
/// (the challenge seed is sampled by the verifier here). The coin-toss fields
/// (`lpn_seed_*`) likewise have no emp counterpart.
pub mod emp_wire {

    use super::{ReceiverExtend, SenderExtend};
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
}

/// Derivations that emp computes internally.
#[cfg(feature = "emp")]
pub mod emp_compat {
    use mpz_core::Block;
    use sha2::{Digest, Sha256};

    /// emp-ot's LPN-seed random-oracle domain separator.
    const LPN_SEED_DOMAIN: &str = "emp-ot:ferret:lpn-seed";

    /// emp-tool `RO` field framing: `u32_le(type) || u32_le(len) || bytes`.
    fn frame(out: &mut Vec<u8>, ty: u32, bytes: &[u8]) {
        out.extend_from_slice(&ty.to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }

    /// emp-ot's `derive_lpn_seed_`: `RO("emp-ot:ferret:lpn-seed", sid)`, using
    /// emp-tool's typed field framing and its default SHA-256 `Hash`, squeezed
    /// to a block (the first 16 bytes of the digest).
    pub fn lpn_seed(sid: Block) -> Block {
        let mut msg = Vec::new();
        frame(&mut msg, 1, LPN_SEED_DOMAIN.as_bytes()); // RO::kStr
        frame(&mut msg, 3, sid.as_bytes()); // RO::kBlock
        let digest = Sha256::digest(&msg);
        Block::from(<[u8; 16]>::try_from(&digest[..16]).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "emp")]
    use crate::ideal::emp_rcot::EmpRCOT;
    use crate::{
        ferret::config::TEST_PARAMS,
        ideal::rcot::IdealRCOT,
        rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
        test::assert_cot,
    };
    use mpz_core::Block;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_ferret() {
        use rand::RngExt;

        let mut rng = StdRng::seed_from_u64(0);
        let delta = rng.random();
        let cot = IdealRCOT::new(rng.random(), delta);

        let mut builder = FerretConfig::builder();

        builder.param_selector(|_, _| TEST_PARAMS);

        let config = builder.build().unwrap();
        let count = TEST_PARAMS.n * 2;

        let mut sender = Sender::new(rng.random(), config.clone(), cot.clone());
        let mut receiver = Receiver::new(rng.random(), config, cot);

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

    const GOLDEN: &str = include_str!("../tests/data/ferret_b11_round.txt");

    /// Returns the value after the `name ` tag in the golden fixture.
    fn golden_line(name: &str) -> &'static str {
        GOLDEN
            .lines()
            .find_map(|l| {
                let (tag, rest) = l.split_once(' ')?;
                (tag == name).then_some(rest)
            })
            .unwrap_or_else(|| panic!("golden is missing `{name}`"))
    }

    /// Decodes a hex field of the golden fixture.
    fn golden_hex(name: &str) -> Vec<u8> {
        let s = golden_line(name);
        assert!(s.len() % 2 == 0, "odd hex length for `{name}`");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// Decodes a 16-byte block field of the golden fixture.
    fn golden_block(name: &str) -> Block {
        Block::from(<[u8; 16]>::try_from(golden_hex(name)).unwrap())
    }

    /// One extension round, with the extend messages run through the emp-ot wire
    /// adapters. Checks their shapes.
    #[test]
    fn test_emp_wire_shapes() {
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

        sender.alloc_bootstrap().unwrap();
        receiver.alloc_bootstrap().unwrap();
        sender.acquire_cot().flush().unwrap();
        receiver.acquire_cot().flush().unwrap();
        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();

        sender.start_extend().unwrap();
        let receiver_extend = receiver.start_extend().unwrap();
        let recv_ext = emp_wire::receiver_extend(&receiver_extend);
        let sender_extend = sender.extend(receiver_extend).unwrap();
        let send = emp_wire::sender_extend(&sender_extend);

        let tree_depth = (TEST_PARAMS.n / TEST_PARAMS.t).ilog2() as usize;
        // emp's sender→receiver stream: one `tree_depth`-block `c` per tree.
        assert_eq!(send.len(), TEST_PARAMS.t as usize * tree_depth * 16);
        // emp sends nothing on the extend from the receiver.
        assert_eq!(recv_ext.len(), 0);
    }

    /// One extension round, byte-for-byte against emp-ot.
    ///
    /// The fixture is `tests/data/ferret_b11_round.txt`, captured from
    /// `tools/dump_ferret_golden.cpp` (`ferret_b11`: t=1170, tree_depth=11,
    /// non-malicious, sid=0) under `EMP_TEST_MODE=1`. The sender's PRG is seeded
    /// with emp-tool's own test-mode gadget-PRG seed, so no reseed hook is needed
    /// on the emp side.
    #[cfg(feature = "emp")]
    #[test]
    fn test_emp_round_c() {
        let params = mpz_core::lpn::LpnParameters {
            n: golden_line("n").parse().unwrap(),
            k: golden_line("k").parse().unwrap(),
            t: golden_line("t").parse().unwrap(),
        };
        let tree_depth: usize = golden_line("tree_depth").parse().unwrap();

        let seed = golden_block("seed");
        let delta = golden_block("delta");
        let gadget_seed = golden_block("gadget_seed");

        let mut builder = FerretConfig::builder();
        builder.param_selector(move |_, _| params);
        let config = builder.build().unwrap();

        let cot = EmpRCOT::new(seed, delta);
        let mut sender = Sender::new(gadget_seed, config.clone(), cot.clone());
        let mut receiver = Receiver::new(gadget_seed, config, cot);

        // A single alloc allocates on both roles (EmpRCOT::alloc does both), so
        // the first round consumes the base correlations from offset 0.
        sender.alloc_bootstrap().unwrap();
        sender.acquire_cot().flush();

        sender.alloc(params.n).unwrap();
        receiver.alloc(params.n).unwrap();

        sender.start_extend().unwrap();
        let re = receiver.start_extend().unwrap();
        let se = sender.extend(re).unwrap();
        let wire = emp_wire::sender_extend(&se);

        let want = golden_hex("first_tree");
        assert!(
            wire.len() >= want.len(),
            "wire too short: {} < {}",
            wire.len(),
            want.len()
        );
        assert_eq!(
            &wire[..tree_depth * 16],
            &want[..],
            "first tree c diverges from emp"
        );

        // Whole round: emp's trace is its b11 round's 1170 tree-sends
        // (t trees), = t * tree_depth * 16 bytes.
        assert_eq!(wire.len(), params.t as usize * tree_depth * 16);
        use sha2::Digest;
        let got = sha2::Sha256::digest(&wire);
        assert_eq!(
            got.as_slice(),
            golden_hex("round_sha256").as_slice(),
            "round c stream diverges from emp"
        );
    }
}
