//! Implement AES-based PRG.

use std::{collections::HashMap, convert::Infallible};

use crate::{Block, aes::AesEncryptor};
use rand::{Rng, RngExt};
use rand_core::{
    SeedableRng, TryCryptoRng, TryRng,
    block::{BlockRng, Generator},
};

/// Struct of PRG Core
#[derive(Clone)]
struct PrgCore {
    aes: AesEncryptor,
    // Stores the counter for each stream id.
    state: HashMap<u64, u64>,
    stream_id: u64,
    counter: u64,
}

impl Generator for PrgCore {
    type Output = [u32; 4 * AesEncryptor::AES_BLOCK_COUNT];

    // Compute 8 encrypted counter blocks at a time.
    #[inline(always)]
    fn generate(&mut self, results: &mut Self::Output) {
        let mut states = [0; AesEncryptor::AES_BLOCK_COUNT].map(
            #[inline(always)]
            |_| {
                let mut block = [0u8; 16];
                let counter = self.counter;
                self.counter += 1;

                block[..8].copy_from_slice(&counter.to_le_bytes());
                block[8..].copy_from_slice(&self.stream_id.to_le_bytes());

                Block::from(block)
            },
        );
        self.aes.encrypt_many_blocks(&mut states);
        *results = bytemuck::cast(states);
    }
}

impl SeedableRng for PrgCore {
    type Seed = Block;

    #[inline(always)]
    fn from_seed(seed: Self::Seed) -> Self {
        let aes = AesEncryptor::new(seed);
        Self {
            aes,
            state: Default::default(),
            stream_id: 0u64,
            counter: 0u64,
        }
    }
}

/// AES-based PRG.
///
/// This PRG is based on AES128 used in counter-mode to generate pseudo-random
/// data streams.
///
/// # Stream ID
///
/// The PRG is configurable with a stream ID, which can be used to generate
/// distinct streams using the same seed. See [`Prg::set_stream_id`].
#[derive(Clone)]
pub struct Prg(BlockRng<PrgCore>);

opaque_debug::implement!(Prg);

impl TryRng for Prg {
    type Error = Infallible;

    #[inline(always)]
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.0.next_word())
    }

    #[inline(always)]
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.0.next_u64_from_u32())
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for Prg {
    type Seed = Block;

    #[inline(always)]
    fn from_seed(seed: Self::Seed) -> Self {
        Prg(BlockRng::new(PrgCore::from_seed(seed)))
    }
}

impl TryCryptoRng for Prg {}

impl Prg {
    /// New Prg with random seed.
    #[inline(always)]
    pub fn new() -> Self {
        Prg::from_seed(rand::random::<Block>())
    }

    /// Create a new PRG from a seed.
    pub fn new_with_seed(seed: [u8; 16]) -> Self {
        Prg::from_seed(Block::from(seed))
    }

    /// Returns the current counter.
    pub fn counter(&self) -> u64 {
        self.0.core.counter
    }

    /// Returns the stream id.
    pub fn stream_id(&self) -> u64 {
        self.0.core.stream_id
    }

    /// Sets the stream id.
    pub fn set_stream_id(&mut self, stream_id: u64) {
        let state = &mut self.0.core.state;
        state.insert(self.0.core.stream_id, self.0.core.counter);

        let counter = state.get(&stream_id).copied().unwrap_or(0);

        self.0.core.stream_id = stream_id;
        self.0.core.counter = counter;
    }

    /// Generate a random bool value.
    #[inline(always)]
    pub fn random_bool(&mut self) -> bool {
        self.random()
    }

    /// Fill a bool slice with random bool values.
    #[inline(always)]
    pub fn random_bools(&mut self, buf: &mut [bool]) {
        for b in buf {
            *b = self.random();
        }
    }

    /// Generate a random byte value.
    #[inline(always)]
    pub fn random_byte(&mut self) -> u8 {
        self.random()
    }

    /// Fill a byte slice with random values.
    #[inline(always)]
    pub fn random_bytes(&mut self, buf: &mut [u8]) {
        self.fill_bytes(buf);
    }

    /// Generate a random block.
    #[inline(always)]
    pub fn random_block(&mut self) -> Block {
        self.random()
    }

    /// Fill a block slice with random block values.
    #[inline(always)]
    pub fn random_blocks(&mut self, buf: &mut [Block]) {
        let bytes: &mut [u8] = bytemuck::cast_slice_mut(buf);
        self.fill_bytes(bytes);
    }
}

impl Default for Prg {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prg_ne() {
        let mut prg = Prg::new();
        let mut x = vec![Block::ZERO; 2];
        prg.random_blocks(&mut x);
        assert_ne!(x[0], x[1]);
    }

    #[test]
    fn test_prg_streams_are_distinct() {
        let mut prg = Prg::from_seed(Block::ZERO);
        let mut x = vec![Block::ZERO; 2];
        prg.random_blocks(&mut x);

        let mut y = vec![Block::ZERO; 2];
        prg.set_stream_id(1);
        prg.random_blocks(&mut y);

        assert_ne!(x[0], y[0]);
    }

    #[test]
    fn test_prg_state_persisted() {
        let mut prg = Prg::from_seed(Block::ZERO);
        let mut x = vec![Block::ZERO; 2];
        prg.random_blocks(&mut x);

        let counter = prg.counter();
        assert_ne!(counter, 0);

        prg.set_stream_id(1);
        prg.set_stream_id(0);

        assert_eq!(prg.counter(), counter);
    }
}
