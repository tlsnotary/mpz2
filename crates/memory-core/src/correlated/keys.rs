use std::ops::Add;

use blake3::{Hash, Hasher};
use mpz_core::{
    Block,
    bitvec::{BitSlice, BitVec},
};
use rand::{RngExt, distr::StandardUniform, prelude::Distribution};
use rangeset::ops::Set;

use crate::{
    RangeSet, Slice,
    correlated::{Delta, MAC_ONE, MAC_ZERO, MacCommitment, macs::Mac},
    store::{Store, StoreError},
};

type Result<T> = core::result::Result<T, KeyStoreError>;

/// MAC key.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Key(Block);

impl Key {
    /// Returns the pointer bit.
    #[inline]
    pub fn pointer(&self) -> bool {
        self.0.lsb()
    }

    /// Adjusts the truth value of the corresponding MAC.
    #[inline]
    pub fn adjust(&mut self, adjust: bool, delta: &Delta) {
        self.0 ^= if adjust {
            delta.as_block()
        } else {
            &Block::ZERO
        };

        // Setting LSB(key) == 0 to enable the prover to store the authenticated
        // bit in LSB(MAC).
        self.0.set_lsb(false);
    }

    /// Commits to the MACs of a value.
    #[inline]
    pub fn commit(&self, id: u64, delta: &Delta) -> MacCommitment {
        let macs = [self.0, self.0 ^ delta.as_block()];

        let commitments = macs.map(|mac| {
            let mut hasher = Hasher::new();
            hasher.update(&id.to_be_bytes());
            hasher.update(mac.as_bytes());
            Block::new(hasher.finalize().as_bytes()[..16].try_into().unwrap())
        });

        MacCommitment(commitments)
    }

    /// Returns a MAC for the given bit.
    #[inline]
    pub fn auth(&self, bit: bool, delta: &Delta) -> Mac {
        Mac::new(self.0 ^ if bit { delta.as_block() } else { &Block::ZERO })
    }

    /// Returns the key block.
    #[inline]
    pub fn as_block(&self) -> &Block {
        &self.0
    }

    /// Converts a slice of keys to a slice of blocks.
    #[inline]
    pub fn as_blocks(slice: &[Self]) -> &[Block] {
        // Safety:
        // Key is a newtype of block.
        unsafe { &*(slice as *const [Self] as *const [Block]) }
    }

    /// Converts a `Vec` of blocks to a `Vec` of keys.
    #[inline]
    pub fn from_blocks(blocks: Vec<Block>) -> Vec<Self> {
        // Safety:
        // Key is a newtype of block.
        unsafe { std::mem::transmute(blocks) }
    }

    /// Converts a `Vec` of keys to a `Vec` of blocks.
    #[inline]
    pub fn into_blocks(keys: Vec<Self>) -> Vec<Block> {
        // Safety:
        // Key is a newtype of block.
        unsafe { std::mem::transmute(keys) }
    }
}

impl From<Key> for Block {
    #[inline]
    fn from(key: Key) -> Block {
        key.0
    }
}

impl From<Block> for Key {
    #[inline]
    fn from(block: Block) -> Key {
        Key(block)
    }
}

impl Add<Key> for Key {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Key) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Add<&Key> for Key {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Key) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Add<Key> for &Key {
    type Output = Key;

    #[inline]
    fn add(self, rhs: Key) -> Key {
        Key(self.0 ^ rhs.0)
    }
}

impl Add<&Key> for &Key {
    type Output = Key;

    #[inline]
    fn add(self, rhs: &Key) -> Key {
        Key(self.0 ^ rhs.0)
    }
}

impl Distribution<Key> for StandardUniform {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Key {
        Key(rng.random())
    }
}

/// A linear store which manages correlated MAC keys.
#[derive(Debug, Clone)]
pub struct KeyStore {
    keys: Store<Key>,
    delta: Delta,
    /// Key for public 1 MAC.
    public_one: Key,
    /// Keys used for either OT or for transfering MACs directly.
    used: RangeSet,
}

impl KeyStore {
    /// Creates a new key store.
    #[inline]
    pub fn new(delta: Delta) -> Self {
        let mut public_one = Key(MAC_ONE ^ delta.as_block());
        // By definition, LSB(public_one) == 0. We set it here again for
        // expliciteness.
        public_one.0.set_lsb(false);
        Self {
            keys: Store::default(),
            delta,
            public_one,
            used: RangeSet::default(),
        }
    }

    /// Returns the global correlation, `Δ`.
    #[inline]
    pub fn delta(&self) -> &Delta {
        &self.delta
    }

    /// Returns whether all the keys are set.
    #[inline]
    pub fn is_set(&self, slice: Slice) -> bool {
        self.keys.is_set(slice)
    }

    /// Returns the ranges which have keys set.
    #[inline]
    pub fn set_ranges(&self) -> &RangeSet {
        self.keys.set_ranges()
    }

    /// Returns whether any of the keys are used.
    #[inline]
    pub fn is_used(&self, slice: Slice) -> bool {
        !slice.to_range().is_disjoint(&self.used)
    }

    /// Allocates uninitialized memory.
    #[inline]
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.keys.alloc(len)
    }

    /// Allocates memory with the given keys.
    #[inline]
    pub fn alloc_with(&mut self, keys: &[Key]) -> Slice {
        self.keys.alloc_with(keys)
    }

    /// Returns keys if they are set.
    ///
    /// # Security
    ///
    /// **Never** use this method to transfer MACs to the receiver.
    ///
    /// Use [`authenticate`](Self::authenticate) or
    /// [`oblivious_transfer`](Self::oblivious_transfer) instead.
    #[inline]
    pub fn try_get(&self, slice: Slice) -> Result<&[Key]> {
        self.keys.try_get(slice).map_err(From::from)
    }

    /// Sets keys, returning an error if the keys are already set.
    #[inline]
    pub fn try_set(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.keys.try_set(slice, keys).map_err(From::from)
    }

    /// Sets keys for public data, returning an error if the keys are already
    /// set.
    #[inline]
    pub fn try_set_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        let keys = data
            .iter()
            .map(|bit| if *bit { self.public_one } else { Key(MAC_ZERO) })
            .collect::<Vec<_>>();
        self.keys.try_set(slice, &keys).map_err(From::from)
    }

    /// Returns the pointer bits of the keys if they are set.
    pub fn try_get_bits(&self, slice: Slice) -> Result<impl Iterator<Item = bool> + '_> {
        self.keys
            .try_get(slice)
            .map(|keys| keys.iter().map(|key| key.pointer()))
            .map_err(From::from)
    }

    /// Commits to the MACs of the given slice.
    pub fn commit(&self, slice: Slice) -> Result<Vec<MacCommitment>> {
        let start_id = slice.ptr.0;
        let keys = self.keys.try_get(slice)?;

        let commitments = keys
            .iter()
            .enumerate()
            .map(|(i, key)| key.commit((start_id + i) as u64, &self.delta))
            .collect();

        Ok(commitments)
    }

    /// Authenticates the data, returning MACs.
    ///
    /// Returns an error if the keys are already used.
    ///
    /// # Panics
    ///
    /// Panics if the bit slice is not the same length as the slice.
    pub fn authenticate<'a>(
        &'a mut self,
        slice: Slice,
        data: &'a BitSlice,
    ) -> Result<impl Iterator<Item = Mac> + 'a> {
        assert_eq!(
            slice.size,
            data.len(),
            "bits are not the same length as the slice"
        );

        if self.is_used(slice) {
            return Err(KeyStoreError::AlreadyAssigned(slice));
        } else if !self.keys.is_set(slice) {
            return Err(KeyStoreError::Uninit(slice));
        }

        let range = slice.to_range();
        self.used |= range;

        Ok(data
            .iter()
            .zip(self.keys.try_get(slice).expect("keys should be set"))
            .map(|(bit, key)| key.auth(*bit, &self.delta)))
    }

    /// Returns the keys to send using oblivious transfer.
    ///
    /// Returns an error if the keys are already used.
    pub fn oblivious_transfer(&mut self, slice: Slice) -> Result<&[Key]> {
        if self.is_used(slice) {
            return Err(KeyStoreError::AlreadyAssigned(slice));
        } else if !self.keys.is_set(slice) {
            return Err(KeyStoreError::Uninit(slice));
        }

        let keys = self.keys.try_get(slice).expect("keys should be set");
        self.used |= slice.to_range();

        Ok(keys)
    }

    /// Adjusts the keys for the given range.
    ///
    /// # Panics
    ///
    /// Panics if the bit slice is not the same length as the range.
    pub fn adjust(&mut self, slice: Slice, adjust: &BitSlice) -> Result<()> {
        assert_eq!(
            slice.size,
            adjust.len(),
            "bits are not the same length as the slice"
        );

        self.keys
            .try_get_slice_mut(slice)?
            .iter_mut()
            .zip(adjust)
            .for_each(|(key, adjust)| {
                key.adjust(*adjust, &self.delta);
            });

        Ok(())
    }

    /// Verifies MACs, writing authenticated data back into the provided bit
    /// slice.
    ///
    /// # Panics
    ///
    /// Panics if the ranges and bits are not the same length.
    ///
    /// # Arguments
    ///
    /// * `ranges` - Ranges of the MACs.
    /// * `bits` - MAC pointer bits.
    /// * `proof` - Hash which proves knowledge of the MACs.
    pub fn verify(&self, ranges: &RangeSet, bits: &mut BitSlice, proof: Hash) -> Result<()> {
        assert_eq!(
            ranges.len(),
            bits.len(),
            "ranges and bits are not the same length"
        );

        if ranges.is_empty() {
            return Ok(());
        }

        let mut data = BitVec::with_capacity(bits.len());
        let mut hasher = Hasher::new();
        let mut idx = 0;
        for range in ranges.iter() {
            let slice = Slice::from_range_unchecked(range);
            self.keys
                .try_get(slice)?
                .iter()
                .zip(&bits[idx..idx + slice.size])
                .for_each(|(key, mac_bit)| {
                    let value = key.pointer() ^ *mac_bit;
                    let expected_mac = key.auth(value, &self.delta);

                    data.push(value);
                    hasher.update(expected_mac.as_bytes());
                });
            idx += slice.size;
        }

        if hasher.finalize() != proof {
            return Err(KeyStoreError::Verify);
        }

        bits.copy_from_bitslice(&data);

        Ok(())
    }
}

/// Error for [`KeyStore`].
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("invalid slice: {}", .0)]
    InvalidSlice(Slice),
    #[error("keys are not initialized: {}", .0)]
    Uninit(Slice),
    #[error("keys are already set: {}", .0)]
    AlreadySet(Slice),
    #[error("keys are already assigned: {}", .0)]
    AlreadyAssigned(Slice),
    #[error("MAC verification error")]
    Verify,
}

impl From<StoreError> for KeyStoreError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::InvalidSlice(slice) => Self::InvalidSlice(slice),
            StoreError::Uninit(slice) => Self::Uninit(slice),
            StoreError::AlreadySet(slice) => Self::AlreadySet(slice),
        }
    }
}
