//! Keccak-256 hash function.

use std::{mem, sync::Arc};

use mpz_circuits::{KECCAK_PERMUTE, circuits::xor};
use mpz_vm_core::{
    Call, CallableExt, Vm, VmError,
    memory::{
        Array, FromRaw, MemoryExt, Slice, ToRaw, Vector, ViewExt,
        binary::{Binary, U8, U64},
    },
};

/// Initial value of the sponge state.
const IV: [u64; 25] = [0x0000000000000000; 25];

/// Number of words comprising the rate part of the state.
const RATE_WORDS: usize = 17;

/// Number of words comprising the capacity part of the state.
const CAPACITY_WORDS: usize = 8;

/// Domain separation byte of the padding.
const DOMAIN_SEP_PAD: u8 = 0x01;

/// Trailing byte of the padding.
const TRAILING_PAD: u8 = 0x80;

/// Input block size in bits.
const BLOCK_SIZE: usize = 1088;

/// An input block.
#[derive(Debug, Default, Clone)]
struct Block {
    data: Vec<Slice>,
    /// Bitlength of `data`.
    len: usize,
}

/// Keccak-256 hasher.
#[derive(Debug, Default, Clone)]
pub struct Keccak256 {
    state: Option<Array<U64, 25>>,
    /// Input block which hasn't yet been absorbed.
    block: Block,
}

impl Keccak256 {
    /// Creates a new Keccak-256 hasher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new Keccak-256 hasher initialized with the IV.
    pub fn new_with_init(vm: &mut dyn Vm<Binary>) -> Result<Self, Keccak256Error> {
        let mut hasher = Self::new();
        hasher.get_or_init_state(vm)?;

        Ok(hasher)
    }

    /// Creates a new Keccak-256 hasher with the provided state.
    ///
    /// # Arguments
    ///
    /// * `state` - The state of the hasher.
    pub fn new_from_state(state: Array<U64, 25>) -> Self {
        Self {
            state: Some(state),
            block: Block::default(),
        }
    }

    /// Returns `true` if the hasher has no data in the internal buffer.
    pub fn is_empty(&self) -> bool {
        self.block.len == 0
    }

    /// Returns the hash state.
    pub fn state(&self) -> Option<Array<U64, 25>> {
        self.state
    }

    /// Updates the hash with the provided data.
    fn update_slice(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        mut data: Slice,
    ) -> Result<(), Keccak256Error> {
        if data.len() == 0 {
            return Ok(());
        }

        // Add the data to the last block.
        let diff = BLOCK_SIZE - self.block.len;
        let (left, right) = data.split_at(diff.min(data.len()));
        self.block.data.push(left);
        self.block.len += left.len();
        data = right;

        // Those blocks which are full will be absorbed now.
        let mut absorb = Vec::new();

        if self.block.len == BLOCK_SIZE {
            absorb.push(mem::take(&mut self.block));
        }

        // Partition the rest of the data into blocks.
        while data.len() > 0 {
            let (left, right) = data.split_at(BLOCK_SIZE.min(data.len()));
            let block = Block {
                data: vec![left],
                len: left.len(),
            };
            data = right;

            if block.len == BLOCK_SIZE {
                absorb.push(block);
            } else {
                self.block = block;
                debug_assert!(data.len() == 0);
            }
        }

        for block in absorb {
            self.absorb_block(vm, block)?
        }

        Ok(())
    }

    /// Updates the hash with the provided data.
    pub fn update(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        data: &Vector<U8>,
    ) -> Result<(), Keccak256Error> {
        self.update_slice(vm, data.to_raw())
    }

    /// Finalizes the hash, consuming the hasher.
    pub fn finalize(mut self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 32>, Keccak256Error> {
        // Padding bitlength.
        let mut pad_bitlen = BLOCK_SIZE - self.block.len;
        if pad_bitlen < 16 {
            // If there's no room for domain separation and trailing bytes,
            // the padding will span an additional block.
            pad_bitlen += BLOCK_SIZE;
        }

        // Padding bytelength.
        let pad_len = pad_bitlen / 8;
        let padding = vm.alloc_vec(pad_len)?;
        vm.mark_public(padding)?;

        let mut padding_data = vec![0u8; pad_len];
        padding_data[0] = DOMAIN_SEP_PAD;
        padding_data[pad_len - 1] = TRAILING_PAD;

        vm.assign(padding, padding_data)?;
        vm.commit(padding)?;

        self.update(vm, &padding)?;

        let slice = self
            .state
            .expect("state was initialized")
            .get::<4>(0)
            .expect("state has 25 elements")
            .to_raw();
        let out = <Array<U8, 32> as FromRaw<Binary>>::from_raw(slice);

        Ok(out)
    }

    /// Absorbs a single `block`.
    fn absorb_block(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        block: Block,
    ) -> Result<(), Keccak256Error> {
        let state = self.get_or_init_state(vm)?;

        // Separate the state into the rate and capacity parts.
        let rate = state.get::<RATE_WORDS>(0).expect("state has 25 elements");
        let capacity = state
            .get::<CAPACITY_WORDS>(RATE_WORDS)
            .expect("state has 25 elements");

        // Absorb the block into the rate.
        let mut builder = Call::builder(Arc::new(xor(BLOCK_SIZE)));
        for slice in block.data {
            builder = builder.arg(slice);
        }
        let call = builder.arg(rate).build().expect("call should be valid");
        let new_rate: Array<U64, RATE_WORDS> = vm.call(call)?;

        // Permute the state.
        let call = Call::builder(KECCAK_PERMUTE.clone())
            .arg(new_rate)
            .arg(capacity)
            .build()
            .expect("call should be valid");

        self.state = Some(vm.call(call)?);

        Ok(())
    }

    fn get_or_init_state(
        &mut self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<Array<U64, 25>, Keccak256Error> {
        if let Some(state) = self.state {
            Ok(state)
        } else {
            let state = vm.alloc()?;
            vm.mark_public(state)?;
            vm.assign(state, IV)?;
            vm.commit(state)?;

            Ok(state)
        }
    }
}

/// Error for [`Keccak256`].
#[derive(Debug, thiserror::Error)]
#[error("keccak256 error: {0}")]
pub struct Keccak256Error(#[from] VmError);

#[cfg(test)]
mod tests {
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_vm_core::prelude::*;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;
    use rstest::*;

    #[rstest]
    #[case::empty(vec![])]
    #[case::less_than_block(vec![1])]
    #[case::less_than_block_many(vec![1, 3, 9, 10])]
    #[case::exactly_one_block_no_pad_many(vec![100, 30, 6])]
    #[case::exactly_one_block_many(vec![100, 30, 8])]
    #[case::exactly_one_block_minus_2(vec![136])]
    #[case::exactly_one_block_minus_1(vec![137])]
    #[case::exactly_one_block(vec![138])]
    #[case::multiple_blocks(vec![138, 136])]
    #[case::multiple_large(vec![280, 280])]
    #[case::multiple_large_and_partial(vec![138, 276, 63])]
    #[tokio::test]
    async fn test_keccak256(#[case] lens: Vec<usize>) {
        use sha2::Digest;

        let mut rng = StdRng::seed_from_u64(0);
        let data: Vec<_> = lens
            .into_iter()
            .map(|len| (0..len).map(|_| rng.random::<u8>()).collect::<Vec<_>>())
            .collect();

        let (vm_0, vm_1) = (IdealVm::default(), IdealVm::default());

        let (mut ctx_a, mut ctx_b) = test_st_context(8);

        let (a, b) = tokio::join!(
            async {
                let mut hasher = Keccak256::new();
                let mut vm = vm_0;

                for data in &data {
                    let data_ref = vm.alloc_vec::<U8>(data.len()).unwrap();
                    vm.mark_public(data_ref).unwrap();
                    vm.assign(data_ref, data.clone()).unwrap();
                    vm.commit(data_ref).unwrap();

                    hasher.update(&mut vm, &data_ref).unwrap();
                }

                let out = hasher.finalize(&mut vm).unwrap();
                let mut out = vm.decode(out).unwrap();

                vm.execute_all(&mut ctx_a).await.unwrap();

                out.try_recv().unwrap().unwrap()
            },
            async {
                let mut hasher = Keccak256::new();
                let mut vm = vm_1;

                for data in &data {
                    let data_ref = vm.alloc_vec::<U8>(data.len()).unwrap();
                    vm.mark_public(data_ref).unwrap();
                    vm.assign(data_ref, data.clone()).unwrap();
                    vm.commit(data_ref).unwrap();

                    hasher.update(&mut vm, &data_ref).unwrap();
                }

                let out = hasher.finalize(&mut vm).unwrap();
                let mut out = vm.decode(out).unwrap();

                vm.execute_all(&mut ctx_b).await.unwrap();

                out.try_recv().unwrap().unwrap()
            }
        );

        assert_eq!(a, b);

        let mut hasher = sha3::Keccak256::new();
        for data in &data {
            hasher.update(data);
        }
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(a, expected);
    }
}
