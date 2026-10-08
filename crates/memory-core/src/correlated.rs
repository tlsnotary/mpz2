//! Correlated memory store.
//!
//! This module provides a memory store for protocols which use authenticated
//! MACs with a linear correlation structure:
//!
//! `M = k + x * Δ`
//!
//! Where `k` is a random key, `x` is the authenticated value, and `Δ` is a
//! global correlation value referred to as delta.
//!
//! One party, the Sender, holds the key `k` and delta `Δ`. The other party, the
//! Receiver, holds the MAC `M`.
//!
//! `M` can be viewed as a MAC on `x` which can be verified by the Sender by
//! checking the relation above holds.
//!
//! # Fields
//!
//! At the moment we only support the binary field, where the MACs and keys are
//! in the extension field `GF(2^128)`.
//!
//! # Pointer bit
//!
//! The least significant bit of the keys and delta `Δ` is used as a pointer
//! bit. This bit encodes the truth value of the MAC `M` in the following way:
//!
//! The pointer bit of delta `Δ` is fixed to 1, which ensures the relation
//! `LSB(M) = LSB(k) ^ x` is present. With this, the value `x` can be recovered
//! easily given only 1 bit of the MAC `M` and of the key `k`.
//!
//! Note that `k` is sampled uniformly at random, so its pointer bit can be
//! viewed as a one-time pad on `x`. A Receiver presented with a MAC `M` alone
//! learns nothing about `x`.
//!
//! Notice also that this can be viewed as an additive secret sharing of the
//! value `x`, where the Sender holds `LSB(k)` and the Receiver holds `LSB(M)`
//! such that `x = LSB(k) ^ LSB(M)`.
//!
//! # Derandomization
//!
//! During the offline-phase, the Sender and Receiver can compute MACs on random
//! values provided by the Receiver and later derandomize them.
//!
//! For example, given a MAC `M = k + r * Δ` where `r` is a random value known
//! only to the Receiver, the Receiver can obtain a MAC on the value `x` by
//! sending `d = x ^ r`.
//!
//! The Sender then adjusts their key `k` by computing `k = k + d * Δ` and sets
//! `LSB(k) = 0`.
//!
//! The Receiver adjusts their MAC by setting `LSB(M) = x`.
//!
//! In the end, the relationships hold `M = k + x * Δ` and `LSB(M) = LSB(k) ^
//! x`.

mod keys;
mod macs;

use std::ops::BitXor;

pub use keys::{Key, KeyStore, KeyStoreError};
pub use macs::{Mac, MacStore, MacStoreError};

use mpz_core::Block;

use blake3::Hasher;
use rand::{CryptoRng, Rng, RngExt, distr::StandardUniform, prelude::Distribution};
use serde::{Deserialize, Serialize};

/// Block for public 0 MAC.
pub(crate) const MAC_ZERO: Block = Block::new([
    146, 239, 91, 41, 80, 62, 197, 196, 204, 121, 176, 38, 171, 216, 63, 120,
]);
/// Block for public 1 MAC.
pub(crate) const MAC_ONE: Block = Block::new([
    219, 104, 26, 50, 91, 130, 201, 178, 144, 31, 95, 155, 206, 113, 5, 103,
]);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Delta(Block);

impl Delta {
    /// Creates a new Delta, setting the pointer bit to 1.
    #[inline]
    pub fn new(mut value: Block) -> Self {
        value.set_lsb(true);
        Self(value)
    }

    /// Generate a random block using the provided RNG
    #[inline]
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::new(rng.random())
    }

    /// Returns the inner block
    #[inline]
    pub fn as_block(&self) -> &Block {
        &self.0
    }

    /// Returns the inner block
    #[inline]
    pub fn into_inner(self) -> Block {
        self.0
    }
}

impl Distribution<Delta> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Delta {
        Delta::new(self.sample(rng))
    }
}

impl From<Delta> for Block {
    fn from(val: Delta) -> Self {
        val.0
    }
}

impl AsRef<Block> for Delta {
    fn as_ref(&self) -> &Block {
        &self.0
    }
}

impl BitXor<Block> for Delta {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: Block) -> Block {
        self.0 ^ rhs
    }
}

impl BitXor<Delta> for Block {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: Delta) -> Block {
        self ^ rhs.0
    }
}

impl BitXor<Block> for &Delta {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: Block) -> Block {
        self.0 ^ rhs
    }
}

impl BitXor<&Block> for Delta {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: &Block) -> Block {
        self.0 ^ rhs
    }
}

impl BitXor<&Delta> for Block {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: &Delta) -> Block {
        self ^ rhs.0
    }
}

impl BitXor<Delta> for &Block {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: Delta) -> Block {
        self ^ rhs.0
    }
}

impl BitXor<&Delta> for &Block {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: &Delta) -> Block {
        self ^ rhs.0
    }
}

/// Commitment to a values MACs.
///
/// This is a hash of the MAC for each truth value of a bit.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct MacCommitment(pub(crate) [Block; 2]);

impl MacCommitment {
    pub fn check(&self, id: u64, value: bool, mac: &Mac) -> Result<(), MacCommitmentError> {
        let [low, high] = &self.0;
        let select = &self.0[value as usize];

        // Commitments must be different.
        if low == high {
            return Err(MacCommitmentError {
                id,
                kind: MacCommitmentErrorKind::Duplicate,
            });
        }

        let mut hasher = Hasher::new();
        hasher.update(&id.to_be_bytes());
        hasher.update(mac.as_bytes());
        let out: [u8; 16] = hasher.finalize().as_bytes()[0..16]
            .try_into()
            .expect("16 bytes");
        let expected = Block::from(out);
        if &expected != select {
            return Err(MacCommitmentError {
                id,
                kind: MacCommitmentErrorKind::Invalid,
            });
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid MAC commitment for id {id}, kind: {kind:?}")]
pub struct MacCommitmentError {
    id: u64,
    kind: MacCommitmentErrorKind,
}

#[derive(Debug)]
enum MacCommitmentErrorKind {
    Duplicate,
    Invalid,
}

#[cfg(test)]
mod tests {
    use mpz_core::{bitvec::BitVec, prg::Prg};
    use mpz_ot_core::{cot::COTReceiverOutput, ideal::cot::IdealCOT};
    use rand::{SeedableRng, rngs::StdRng};

    use crate::Slice;

    use super::*;

    #[test]
    fn test_correlated_store() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let mut cot = IdealCOT::new(delta.into_inner());

        let mut keys = KeyStore::new(delta);
        let mut macs = MacStore::default();

        let val_a = BitVec::from_iter((0..128).map(|_| rng.random::<bool>()));
        let val_b = BitVec::from_iter((0..128).map(|_| rng.random::<bool>()));

        let keys_a = (0..128).map(|_| rng.random()).collect::<Vec<_>>();
        let keys_b = (0..128).map(|_| rng.random()).collect::<Vec<_>>();

        let ref_a_keys = keys.alloc_with(&keys_a);
        let ref_b_keys = keys.alloc_with(&keys_b);

        let ref_a_macs = macs.alloc(128);
        let ref_b_macs = macs.alloc(128);

        let macs_a = keys
            .authenticate(ref_a_keys, &val_a)
            .unwrap()
            .collect::<Vec<_>>();
        let keys_b = keys.oblivious_transfer(ref_b_keys).unwrap().to_vec();

        let choices: Vec<_> = val_b.iter().by_vals().collect();
        let (_, COTReceiverOutput { msgs: macs_b, .. }) = cot
            .transfer(&choices, &Key::into_blocks(keys_b.clone()))
            .unwrap();

        let macs_b = Mac::from_blocks(macs_b);

        macs.try_set(ref_a_macs, &macs_a).unwrap();
        macs.try_set(ref_b_macs, &macs_b).unwrap();

        assert!(keys.is_set(ref_a_keys));
        assert!(keys.is_set(ref_b_keys));
        assert!(macs.is_set(ref_a_macs));
        assert!(macs.is_set(ref_b_macs));

        let key_bits_a = BitVec::from_iter(keys.try_get_bits(ref_a_keys).unwrap());
        let key_bits_b = BitVec::from_iter(keys.try_get_bits(ref_b_keys).unwrap());

        let mac_bits_a = BitVec::from_iter(macs.try_get_bits(ref_a_macs).unwrap());
        let mac_bits_b = BitVec::from_iter(macs.try_get_bits(ref_b_macs).unwrap());

        let val_a_recovered = key_bits_a ^ mac_bits_a;
        let val_b_recovered = key_bits_b ^ mac_bits_b;

        assert_eq!(val_a, val_a_recovered);
        assert_eq!(val_b, val_b_recovered);

        let (mut bits, hash) = macs
            .prove(&Slice::to_rangeset([ref_a_macs, ref_b_macs]))
            .unwrap();

        keys.verify(
            &Slice::to_rangeset([ref_a_keys, ref_b_keys]),
            &mut bits,
            hash,
        )
        .unwrap();

        assert_eq!(&val_a, &bits[0..128]);
        assert_eq!(&val_b, &bits[128..]);
    }

    #[test]
    fn test_adjust() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let mut key_store = KeyStore::new(delta);
        let mut mac_store = MacStore::default();

        let keys = (0..128).map(|_| rng.random()).collect::<Vec<Key>>();
        let masks = BitVec::from_iter((0..128).map(|_| rng.random::<bool>()));
        let macs = keys
            .iter()
            .zip(masks.iter().by_vals())
            .map(|(key, mask)| key.auth(mask, &delta))
            .collect::<Vec<Mac>>();

        let ref_keys = key_store.alloc_with(&keys);
        let ref_macs = mac_store.alloc_with(&macs);

        let data = BitVec::from_iter((0..128).map(|_| rng.random::<bool>()));

        let mut adjust = masks;
        adjust ^= &data;

        key_store.adjust(ref_keys, &adjust).unwrap();
        mac_store.adjust(ref_macs, &data).unwrap();

        assert!(
            key_store
                .try_get(ref_keys)
                .unwrap()
                .iter()
                .all(|key| !key.pointer())
        );
        assert_eq!(
            mac_store
                .try_get(ref_macs)
                .unwrap()
                .iter()
                .map(|mac| mac.pointer())
                .collect::<Vec<_>>(),
            data.iter().by_vals().collect::<Vec<_>>()
        );

        let keys = key_store.try_get(ref_keys).unwrap();
        let macs = mac_store.try_get(ref_macs).unwrap();

        assert!(
            keys.iter()
                .zip(macs)
                .all(|(key, mac)| &key.auth(mac.pointer(), &delta) == mac)
        )
    }

    #[test]
    fn test_public_macs_are_uniform() {
        let mut prg = Prg::new_with_seed(*b"publicmacuniform");
        let mut zero = Block::random(&mut prg);
        let mut one = Block::random(&mut prg);

        zero.set_lsb(false);
        one.set_lsb(true);

        assert_eq!(MAC_ZERO, zero);
        assert_eq!(MAC_ONE, one);
        assert!(!MAC_ZERO.lsb());
        assert!(MAC_ONE.lsb());
    }
}
