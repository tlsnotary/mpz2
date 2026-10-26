//! Derivations that emp computes internally.

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
pub(crate) fn lpn_seed(sid: Block) -> Block {
    let mut msg = Vec::new();
    frame(&mut msg, 1, LPN_SEED_DOMAIN.as_bytes()); // RO::kStr
    frame(&mut msg, 3, sid.as_bytes()); // RO::kBlock
    let digest = Sha256::digest(&msg);
    Block::from(<[u8; 16]>::try_from(&digest[..16]).unwrap())
}
