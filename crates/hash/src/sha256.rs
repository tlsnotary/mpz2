//! SHA-256 hash function.

use std::{
    array::from_fn,
    sync::{Arc, LazyLock},
};

use itybity::ToBits;
use mpz_circuits::{Circuit, CircuitBuilder, SHA256_COMPRESS};
use mpz_core::bitvec::BitVec;
use mpz_vm_core::{
    Call, CallableExt, Vm, VmError,
    memory::{
        Array, MemoryExt, Slice, ToRaw, Vector, ViewExt,
        binary::{Binary, U8, U32},
    },
};

// Serializes the state as bytes in big-endian order.
static SERIALIZE_STATE: LazyLock<Arc<Circuit>> = LazyLock::new(|| {
    let mut builder = CircuitBuilder::new();

    for _ in 0..8 {
        let word: [_; 32] = from_fn(|_| builder.add_input());
        for byte in word.as_chunks::<8>().0.iter().rev() {
            for &bit in byte {
                let out = builder.add_id_gate(bit);
                builder.add_output(out);
            }
        }
    }

    Arc::new(builder.build().unwrap())
});

/// The default initialization vector.
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
/// Block size in bits.
const BLOCK_SIZE: usize = 512;

#[derive(Debug, Default, Clone)]
struct Block {
    data: Vec<Slice>,
    len: usize,
}

/// SHA-256 hasher.
#[derive(Debug, Default, Clone)]
pub struct Sha256 {
    state: Option<Array<U32, 8>>,
    blocks: Vec<Block>,
    processed: usize,
}

impl Sha256 {
    /// Creates a new SHA-256 hasher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new SHA-256 hasher initialized with the IV.
    pub fn new_with_init(vm: &mut dyn Vm<Binary>) -> Result<Self, Sha256Error> {
        let mut hasher = Self::new();
        hasher.get_or_init_state(vm)?;

        Ok(hasher)
    }

    /// Creates a new SHA-256 hasher with the provided state.
    ///
    /// # Arguments
    ///
    /// * `state` - The state of the hasher.
    /// * `processed` - The number of blocks compressed in the state.
    pub fn new_from_state(state: Array<U32, 8>, processed: usize) -> Self {
        Self {
            state: Some(state),
            blocks: Vec::new(),
            processed,
        }
    }

    /// Returns `true` if the hasher has no data in the internal buffer.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns the number of bits in the internal buffer.
    pub fn buffered(&self) -> usize {
        self.blocks.iter().map(|b| b.len).sum::<usize>()
    }

    /// Returns the hash state and the number of blocks compressed so far.
    pub fn state(&self) -> Option<(Array<U32, 8>, usize)> {
        self.state.map(|state| (state, self.processed))
    }

    /// Updates the hash with the provided data.
    fn update_slice(&mut self, mut data: Slice) {
        if data.len() == 0 {
            return;
        }

        // If the last block is not full, add the data to it.
        if let Some(block) = self.blocks.last_mut()
            && block.len < BLOCK_SIZE
        {
            let diff = BLOCK_SIZE - block.len;
            let (left, right) = data.split_at(diff.min(data.len()));
            block.data.push(left);
            block.len += left.len();
            data = right;
        }

        // Partition the rest of the data into blocks.
        while data.len() > 0 {
            let (left, right) = data.split_at(BLOCK_SIZE.min(data.len()));
            self.blocks.push(Block {
                data: vec![left],
                len: left.len(),
            });
            data = right;
        }
    }

    /// Updates the hash with the provided data.
    pub fn update(&mut self, data: &Vector<U8>) {
        self.update_slice(data.to_raw());
    }

    /// Compresses the data in the internal buffer.
    pub fn compress(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), Sha256Error> {
        // Find the position of the last full block.
        let pos = self
            .blocks
            .iter()
            .position(|block| block.len != BLOCK_SIZE)
            .unwrap_or(self.blocks.len());

        let mut state = self.get_or_init_state(vm)?;

        for block in self.blocks.drain(..pos) {
            let mut builder = Call::builder(SHA256_COMPRESS.clone());
            for slice in block.data {
                builder = builder.arg(slice);
            }

            let call = builder
                .arg(state)
                .build()
                .expect("compress circuit should have 512 bit input");

            state = vm.call(call)?;
        }

        self.processed += pos;
        self.state = Some(state);

        debug_assert!(
            self.blocks.len() <= 1,
            "there should be at most one block left"
        );

        Ok(())
    }

    /// Finalizes the hash.
    pub fn finalize(&self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 32>, Sha256Error> {
        let mut hasher = self.clone();

        // begin with the original message of length L bits
        // append a single '1' bit
        // append K '0' bits, where K is the minimum number >= 0 such that (L +
        // 1 + K +
        // 64) is a multiple of 512 append L as a 64-bit big-endian integer,
        // making the total post-processed length a multiple of 512 bits
        // such that the bits in the message are: <original message of length L>
        // 1 <K zeros> <L as 64 bit integer> , (the number of bits will
        // be a multiple of 512)

        let len = (self.processed * BLOCK_SIZE) + self.blocks.iter().map(|b| b.len).sum::<usize>();
        let total_len = (len + 1 + 64).next_multiple_of(BLOCK_SIZE);
        let padding_len = total_len - len;

        let padding = vm.alloc_raw(padding_len)?;
        vm.mark_public_raw(padding)?;

        // The compress circuit expects the input to be encoded as bytes.
        let mut padding_data = BitVec::repeat(false, padding_len);
        // Set the MSB of the first byte to 1.
        padding_data.set(7, true);
        // Set last 64 bits to the length of the original message.
        padding_data[padding_len - 64..]
            .iter_mut()
            .zip((len as u64).to_be_bytes().iter_lsb0())
            .for_each(|(a, b)| a.commit(b));

        vm.assign_raw(padding, padding_data)?;
        vm.commit_raw(padding)?;

        hasher.update_slice(padding);
        hasher.compress(vm)?;

        debug_assert!(hasher.blocks.is_empty());

        let state = hasher.get_or_init_state(vm)?;
        let call = Call::builder(SERIALIZE_STATE.clone())
            .arg(state)
            .build()
            .expect("serialize circuit should have 256 bit input");

        let out = vm.call(call)?;

        Ok(out)
    }

    fn get_or_init_state(&mut self, vm: &mut dyn Vm<Binary>) -> Result<Array<U32, 8>, Sha256Error> {
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

/// Error for [`Sha256`].
#[derive(Debug, thiserror::Error)]
#[error("sha256 error: {0}")]
pub struct Sha256Error(#[from] VmError);

#[cfg(test)]
mod tests {
    use mpz_circuits::evaluate;
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_vm_core::prelude::*;
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use sha2::Digest;

    use super::*;
    use rstest::*;

    #[test]
    fn test_sha256_serialize_state() {
        let output: [u8; 32] = evaluate!(SERIALIZE_STATE, IV).unwrap();
        let expected: Vec<_> = IV.iter().flat_map(|word| word.to_be_bytes()).collect();
        assert_eq!(&output, expected.as_slice());
    }

    #[rstest]
    #[case::empty(vec![])]
    #[case::less_than_block(vec![1])]
    #[case::less_than_block_many(vec![1, 3, 9, 10])]
    #[case::exactly_one_block(vec![64])]
    #[case::multiple_blocks(vec![64, 64])]
    #[case::multiple_blocks_and_partial(vec![64, 64, 63])]
    #[tokio::test]
    async fn test_sha256(#[case] lens: Vec<usize>) {
        let mut rng = StdRng::seed_from_u64(0);
        let data: Vec<_> = lens
            .into_iter()
            .map(|len| (0..len).map(|_| rng.random::<u8>()).collect::<Vec<_>>())
            .collect();

        let (vm_0, vm_1) = (IdealVm::default(), IdealVm::default());

        let (mut ctx_a, mut ctx_b) = test_st_context(8);

        let (a, b) = tokio::join!(
            async {
                let mut hasher = Sha256::new();
                let mut vm = vm_0;

                for data in &data {
                    let data_ref = vm.alloc_vec::<U8>(data.len()).unwrap();
                    vm.mark_public(data_ref).unwrap();
                    vm.assign(data_ref, data.clone()).unwrap();
                    vm.commit(data_ref).unwrap();

                    hasher.update(&data_ref);
                }

                let out = hasher.finalize(&mut vm).unwrap();
                let mut out = vm.decode(out).unwrap();

                vm.execute_all(&mut ctx_a).await.unwrap();

                out.try_recv().unwrap().unwrap()
            },
            async {
                let mut hasher = Sha256::new();
                let mut vm = vm_1;

                for data in &data {
                    let data_ref = vm.alloc_vec::<U8>(data.len()).unwrap();
                    vm.mark_public(data_ref).unwrap();
                    vm.assign(data_ref, data.clone()).unwrap();
                    vm.commit(data_ref).unwrap();

                    hasher.update(&data_ref);
                }

                let out = hasher.finalize(&mut vm).unwrap();
                let mut out = vm.decode(out).unwrap();

                vm.execute_all(&mut ctx_b).await.unwrap();

                out.try_recv().unwrap().unwrap()
            }
        );

        assert_eq!(a, b);

        let mut hasher = sha2::Sha256::default();
        for data in &data {
            hasher.update(data);
        }
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(a, expected);
    }
}
