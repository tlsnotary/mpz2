//! Blake3 hash function.
use std::{
    array::from_fn,
    fmt,
    sync::{Arc, LazyLock},
};

use mpz_circuits::{BLAKE3_COMPRESS, Circuit, CircuitBuilder};
use mpz_core::bitvec::BitVec;
use mpz_vm_core::{
    Call, CallableExt, Vm, VmError,
    memory::{
        Array, MemoryExt, Slice, ToRaw, Vector, ViewExt,
        binary::{Binary, U8, U32},
    },
};

// Serializes the output as bytes in little-endian order.
static SERIALIZE_OUTPUT: LazyLock<Arc<Circuit>> = LazyLock::new(|| {
    let mut builder = CircuitBuilder::new();

    for _ in 0..8 {
        let word: [_; 32] = from_fn(|_| builder.add_input());
        for byte in word.as_chunks::<8>().0 {
            for &bit in byte {
                let out = builder.add_id_gate(bit);
                builder.add_output(out);
            }
        }
    }

    Arc::new(builder.build().unwrap())
});

// The default initialization vector.
// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L35-L37.
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
// Flag values.
// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L27-L30.
const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
// Block size in bits.
const BLOCK_SIZE: usize = blake3::BLOCK_LEN * 8; // 512
// Chunk size in bits.
const CHUNK_SIZE: usize = blake3::CHUNK_LEN * 8; // 8192
// Maximum tree depth supported in blake3.
// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L270.
const MAX_SUBTREE_DEPTH: usize = 54;

#[derive(Debug, Clone)]
struct Block {
    data: Vec<Slice>,
    len: usize,
}

impl Block {
    // Returns the length in bytes, rounding up for partial bytes.
    #[inline]
    fn len_bytes(&self) -> u32 {
        debug_assert!(self.len <= BLOCK_SIZE);
        self.len.div_ceil(8) as u32
    }
}

// Visibility of the initial chaining state.
#[derive(Debug, Copy, Clone)]
enum Visibility {
    #[allow(dead_code)]
    Private,
    Public,
}

// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L166.
#[derive(Debug, Copy, Clone)]
struct ChainingValue(Array<U32, 8>);

impl ChainingValue {
    fn new(
        vm: &mut dyn Vm<Binary>,
        visibility: Visibility,
        value: [u32; 8],
    ) -> Result<Self, Blake3Error> {
        let state = vm.alloc()?;

        match visibility {
            // When keyed hash mode is used, chaining value is initialised with a private key.
            Visibility::Private => vm.mark_private(state)?,
            // When normal hash mode is used, chaining value is initialised with the public IV.
            // We need to use this mode as ZK circuit's DSL (e.g. Noir) only support this now.
            Visibility::Public => vm.mark_public(state)?,
        };

        vm.assign(state, value)?;
        vm.commit(state)?;

        Ok(Self(state))
    }

    fn new_from_state(state: Array<U32, 8>) -> Self {
        Self(state)
    }

    fn set(&mut self, state: Array<U32, 8>) {
        self.0 = state
    }
}

// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L87-L88.
#[derive(Debug, Copy, Clone)]
struct State(Array<U32, 7>);

impl State {
    fn new(
        vm: &mut dyn Vm<Binary>,
        chunk_counter: u64,
        block_len: u32,
    ) -> Result<Self, Blake3Error> {
        let counter_low = chunk_counter as u32;
        let counter_high = (chunk_counter >> 32) as u32;
        #[rustfmt::skip]
        let value = [
            IV[0],             IV[1],             IV[2],             IV[3],
            counter_low,       counter_high,      block_len,
        ];
        let state = vm.alloc()?;
        vm.mark_public(state)?;
        vm.assign(state, value)?;
        vm.commit(state)?;

        Ok(Self(state))
    }
}

// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L88.
// Part of [`State`] in the reference implementation, but separated here to
// reduce memory costs — [`State`] only needs to be initialised twice for every
// [`Chunk`], whereas ['Flags'] needs to be initialised once for every
// [`Block`].
#[derive(Debug, Copy, Clone)]
struct Flags(U32);

impl Flags {
    fn new(vm: &mut dyn Vm<Binary>, value: u32) -> Result<Self, Blake3Error> {
        let state = vm.alloc()?;
        vm.mark_public(state)?;
        vm.assign(state, value)?;
        vm.commit(state)?;

        Ok(Self(state))
    }
}

// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L165-L237.
#[derive(Debug, Clone)]
struct Chunk {
    blocks: Vec<Block>,
    chaining_value: ChainingValue,
    state: State,
    flags: u32,
    counter: u64,
}

impl Chunk {
    fn new(
        vm: &mut dyn Vm<Binary>,
        chaining_value: ChainingValue,
        flags: u32,
        counter: u64,
    ) -> Result<Self, Blake3Error> {
        Ok(Self {
            blocks: Vec::new(),
            chaining_value,
            // The same state can be used with every block, except for the last block,
            // where its length can be smaller than BLOCK_LEN.
            state: State::new(vm, counter, blake3::BLOCK_LEN as u32)?,
            flags,
            counter,
        })
    }

    // Returns the length in bits.
    fn len(&self) -> usize {
        if self.blocks.is_empty() {
            return 0;
        }

        let last_block_len = self
            .blocks
            .last()
            .expect("there should be at least one block")
            .len;

        (self.blocks.len() - 1) * BLOCK_SIZE + last_block_len
    }

    // Updates the hash with the provided data.
    fn update(&mut self, mut data: Slice) {
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

        // Partitions the rest of the data into blocks.
        while data.len() > 0 {
            let (left, right) = data.split_at(BLOCK_SIZE.min(data.len()));
            self.blocks.push(Block {
                data: vec![left],
                len: left.len(),
            });
            data = right;
        }
    }

    // Compresses the data in the internal buffer.
    fn compress(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        is_root: bool,
    ) -> Result<ChainingValue, Blake3Error> {
        let (last_block_len, last_block_len_bytes) = self
            .blocks
            .last()
            .map_or((0, 0), |block| (block.len, block.len_bytes()));

        // Pad the last block if it is not full.
        if last_block_len != BLOCK_SIZE {
            let padding_len = BLOCK_SIZE - last_block_len;
            let padding = vm.alloc_raw(padding_len)?;
            vm.mark_public_raw(padding)?;

            let padding_data = BitVec::repeat(false, padding_len);
            vm.assign_raw(padding, padding_data)?;
            vm.commit_raw(padding)?;

            self.update(padding);
        }

        // Get the number of blocks after padding.
        let no_of_blocks = self.blocks.len();

        // Creates the state for the last block — [`self.state`] can be used
        // with every block, except for the last block, where its length
        // can be smaller than BLOCK_LEN.
        let last_state = if is_root {
            // When there is only 1 chunk to be hashed, i.e. this chunk is the
            // root.
            State::new(vm, 0, last_block_len_bytes)?
        } else {
            State::new(vm, self.counter, last_block_len_bytes)?
        };

        // Compresses block by block.
        for (i, block) in self.blocks.drain(..).enumerate() {
            let mut flags = self.flags;
            let mut state = self.state;

            // Add a domain flag for the first block.
            // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L210.
            if i == 0 {
                flags |= CHUNK_START;
            }
            // Add domain flag(s) and update the state for the last block.
            if i == no_of_blocks - 1 {
                // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L234.
                flags |= CHUNK_END;

                // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L154.
                if is_root {
                    flags |= ROOT;
                }
                state = last_state;
            }

            let flags_state = Flags::new(vm, flags)?;

            let mut builder = Call::builder(BLAKE3_COMPRESS.clone());
            for slice in block.data {
                builder = builder.arg(slice);
            }

            builder = builder.arg(self.chaining_value.0);
            builder = builder.arg(state.0);
            builder = builder.arg(flags_state.0);

            let call = builder
                .build()
                .expect("compress circuit should have 1024 bit input");

            let output: Array<U32, 16> = vm.call(call)?;
            // Truncate the output to the first 256 bits.
            // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L113.
            let truncated: Array<U32, 8> = output
                .get(0)
                .expect("should be able to truncate output to 256 bits");

            // Set this as the new chaining value.
            // P/S: this value is private to the prover.
            self.chaining_value.set(truncated);
        }

        debug_assert!(self.blocks.is_empty(), "there should be no block left");

        Ok(self.chaining_value)
    }
}

/// Blake3 hasher.
/// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L267-L374.
#[derive(Debug, Clone)]
pub struct Blake3 {
    chunk: Chunk,
    initial_cv: ChainingValue,
    cv_stack: Vec<ChainingValue>,
    flags: u32,
    parent_state: State,
}

impl Blake3 {
    fn new_internal(
        vm: &mut dyn Vm<Binary>,
        initial_cv: [u32; 8],
        initial_cv_vis: Visibility,
        flags: u32,
    ) -> Result<Self, Blake3Error> {
        let initial_cv = ChainingValue::new(vm, initial_cv_vis, initial_cv)?;
        // Precomputes the state value required for parent chaining value
        // calculation in `parent_cv`. Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L249-L252.
        let parent_state = State::new(vm, 0, blake3::BLOCK_LEN as u32)?;
        Ok(Self {
            chunk: Chunk::new(vm, initial_cv, flags, 0)?,
            initial_cv,
            cv_stack: Vec::with_capacity(MAX_SUBTREE_DEPTH),
            flags,
            parent_state,
        })
    }

    /// Creates a new Blake3 hasher in the default mode, equivalent to https://docs.rs/blake3/1.8.2/blake3/fn.hash.html.
    /// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L287-L289.
    pub fn new(vm: &mut dyn Vm<Binary>) -> Result<Self, Blake3Error> {
        Self::new_internal(vm, IV, Visibility::Public, 0)
    }

    // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L310-L313.
    fn push_stack(&mut self, cv: ChainingValue) -> Result<(), Blake3Error> {
        if self.cv_stack.len() == MAX_SUBTREE_DEPTH {
            return Err(Blake3Error::new(
                ErrorKind::Tree,
                "Exceeded maximum number of subtrees supported",
            ));
        }
        self.cv_stack.push(cv);
        Ok(())
    }

    // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L315-L318.
    fn pop_stack(&mut self) -> Option<ChainingValue> {
        self.cv_stack.pop()
    }

    // Creates a parent chaining value from children nodes of chaining values.
    // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L239-L255.
    fn parent_cv(
        &self,
        vm: &mut dyn Vm<Binary>,
        left_child_cv: ChainingValue,
        right_child_cv: ChainingValue,
        is_root: bool,
    ) -> Result<ChainingValue, Blake3Error> {
        let mut flags = self.flags | PARENT;
        // When the parent is the root.
        // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L154.
        if is_root {
            flags |= ROOT;
        }
        let flags_state = Flags::new(vm, flags)?;

        let mut builder = Call::builder(BLAKE3_COMPRESS.clone());

        builder = builder.arg(left_child_cv.0);
        builder = builder.arg(right_child_cv.0);
        builder = builder.arg(self.initial_cv.0);
        builder = builder.arg(self.parent_state.0);
        builder = builder.arg(flags_state.0);

        let call = builder
            .build()
            .expect("compress circuit should have 1024 bit input");

        let output: Array<U32, 16> = vm.call(call)?;
        // Truncate the output to the first 256 bits.
        // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L113.
        let truncated: Array<U32, 8> = output
            .get(0)
            .expect("should be able to truncate output to 256 bits");

        // Set this as the new chaining value.
        // P/S: this value is private to the prover.
        let cv = ChainingValue::new_from_state(truncated);

        Ok(cv)
    }

    // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L320-L334.
    // Section 5.1.2 of the BLAKE3 spec explains this algorithm in more detail.
    fn add_chunk_chaining_value(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        mut new_cv: ChainingValue,
        mut total_chunks: u64,
    ) -> Result<(), Blake3Error> {
        // This chunk might complete some subtrees. For each completed subtree,
        // its left child will be the current top entry in the CV stack, and
        // its right child will be the current value of `new_cv`. Pop each left
        // child off the stack, merge it with `new_cv`, and overwrite `new_cv`
        // with the result. After all these merges, push the final value of
        // `new_cv` onto the stack. The number of completed subtrees is given
        // by the number of trailing 0-bits in the new total number of chunks.
        while total_chunks & 1 == 0 {
            let cv = self.pop_stack().expect("should have cv in the stack");
            new_cv = self.parent_cv(vm, cv, new_cv, false)?;
            total_chunks >>= 1;
        }
        self.push_stack(new_cv)?;
        Ok(())
    }

    /// Adds data to the hash state. This can be called any number of times.
    /// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L337-L354.
    pub fn update(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        data: &Vector<U8>,
    ) -> Result<(), Blake3Error> {
        let mut data = data.to_raw();
        while data.len() > 0 {
            // If the current chunk is complete, finalize it and reset the
            // chunk. More data is coming, so this chunk is not the root.
            //
            // This eagerly compresses each chunk so that the efficient
            // algorithm in [`add_chunk_chaining_value`] can be
            // used.
            if self.chunk.len() == CHUNK_SIZE {
                let chunk_cv = self.chunk.compress(vm, false)?;
                let total_chunks = self.chunk.counter + 1;
                self.add_chunk_chaining_value(vm, chunk_cv, total_chunks)?;
                self.chunk = Chunk::new(vm, self.initial_cv, self.flags, total_chunks)?;
            }

            // Compresses data bytes into the current chunk.
            let diff = CHUNK_SIZE - self.chunk.len();
            let (left, right) = data.split_at(diff.min(data.len()));
            self.chunk.update(left);
            data = right;
        }
        Ok(())
    }

    /// Finalizes the hash.
    /// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L357-L373.
    pub fn finalize(&mut self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 32>, Blake3Error> {
        // Starting with the current chunk, compute all the parent chaining
        // values along the right edge of the tree, until we have the
        // root.
        let mut parent_nodes_remaining = self.cv_stack.len();

        let output = if parent_nodes_remaining == 0 {
            // When there is only 1 chunk to be hashed, i.e. self.chunk is the
            // root.
            self.chunk.compress(vm, true)?
        } else {
            let mut output = self.chunk.compress(vm, false)?;

            while parent_nodes_remaining > 1 {
                parent_nodes_remaining -= 1;

                output =
                    self.parent_cv(vm, self.cv_stack[parent_nodes_remaining], output, false)?;
            }
            // Computes the chaining value of the root.
            self.parent_cv(vm, self.cv_stack[0], output, true)?
        };

        let call = Call::builder(SERIALIZE_OUTPUT.clone())
            .arg(output.0)
            .build()
            .expect("serialize output circuit should have 256 bit input");

        let out = vm.call(call)?;

        Ok(out)
    }
}

/// Error for [`Blake3`].
#[derive(Debug, thiserror::Error)]
pub struct Blake3Error {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Blake3Error {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

impl fmt::Display for Blake3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("blake3 error: ")?;

        match self.kind {
            ErrorKind::Vm => f.write_str("vm error")?,
            ErrorKind::Tree => f.write_str("tree construction error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

impl From<VmError> for Blake3Error {
    fn from(value: VmError) -> Self {
        Blake3Error::new(ErrorKind::Vm, value)
    }
}

#[derive(Debug)]
enum ErrorKind {
    Vm,
    Tree,
}

#[cfg(test)]
mod test {
    use mpz_circuits::evaluate;
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_vm_core::prelude::*;

    use blake3::{BLOCK_LEN, CHUNK_LEN, hazmat::HasherExt};
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use rstest::rstest;

    use super::*;

    #[test]
    fn test_serialize_output() {
        let output: [u8; 32] = evaluate!(SERIALIZE_OUTPUT, IV).unwrap();
        let expected: Vec<_> = IV.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert_eq!(&output, expected.as_slice());
    }

    #[rstest]
    #[case::less_than_block(1)]
    #[case::less_than_block_many(10)]
    #[case::exactly_one_block(64)]
    #[case::multiple_blocks(128)]
    #[case::multiple_blocks_and_partial(191)]
    #[case::exactly_one_chunk(1024)]
    #[tokio::test]
    async fn test_chunk_compress(#[case] len: usize) {
        let mut rng = StdRng::seed_from_u64(0);
        let (vm_0, vm_1) = (IdealVm::default(), IdealVm::default());
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let data = (0..len).map(|_| rng.random::<u8>()).collect::<Vec<_>>();

        let (a, b) = tokio::join!(
            async {
                let mut vm = vm_0;
                let chunk_counter = 0;
                let flags = 0u32;
                let cv = ChainingValue::new(&mut vm, Visibility::Public, IV).unwrap();
                let mut chunk_state = Chunk::new(&mut vm, cv, flags, chunk_counter).unwrap();

                let data_ref = vm.alloc_vec::<U8>(data.len()).unwrap();
                vm.mark_public(data_ref).unwrap();
                vm.assign(data_ref, data.clone()).unwrap();
                vm.commit(data_ref).unwrap();
                chunk_state.update(data_ref.to_raw());

                let output = chunk_state.compress(&mut vm, false).unwrap();

                let mut out = vm.decode(output.0).unwrap();
                vm.execute_all(&mut ctx_a).await.unwrap();
                out.try_recv().unwrap().unwrap()
            },
            async {
                let mut vm = vm_1;
                let chunk_counter = 0;
                let flags = 0u32;
                let cv = ChainingValue::new(&mut vm, Visibility::Public, IV).unwrap();
                let mut chunk_state = Chunk::new(&mut vm, cv, flags, chunk_counter).unwrap();

                let data_ref = vm.alloc_vec::<U8>(data.len()).unwrap();
                vm.mark_public(data_ref).unwrap();
                vm.assign(data_ref, data.clone()).unwrap();
                vm.commit(data_ref).unwrap();
                chunk_state.update(data_ref.to_raw());

                let output = chunk_state.compress(&mut vm, false).unwrap();

                let mut out = vm.decode(output.0).unwrap();
                vm.execute_all(&mut ctx_b).await.unwrap();
                out.try_recv().unwrap().unwrap()
            }
        );

        assert_eq!(a, b);

        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(a) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }

        let expected = blake3::Hasher::new().update(&data).finalize_non_root();

        assert_eq!(bytes, expected);
    }

    async fn hash(data: &Vec<Vec<u8>>) -> [u8; 32] {
        let (vm_0, vm_1) = (IdealVm::default(), IdealVm::default());
        let (mut ctx_a, mut ctx_b) = test_st_context(8);

        let (a, b) = tokio::join!(
            async {
                let mut vm = vm_0;
                let mut hasher = Blake3::new(&mut vm).unwrap();

                for data in data {
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
                let mut vm = vm_1;
                let mut hasher = Blake3::new(&mut vm).unwrap();

                for data in data {
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

        a
    }

    #[rstest]
    #[case::empty(vec![])]
    #[case::less_than_block(vec![1])]
    #[case::less_than_block_many(vec![1, 3, 9, 10])]
    #[case::exactly_one_block(vec![64])]
    #[case::multiple_blocks(vec![64, 64])]
    #[case::multiple_blocks_and_partial(vec![64, 64, 63])]
    #[case::exactly_one_chunk(vec![1024])]
    #[case::multiple_chunks(vec![1024, 1024])]
    #[case::multiple_chunks_and_partial(vec![1024, 1024, 45, 899])]
    #[tokio::test]
    async fn test_blocks_and_chunks(#[case] lens: Vec<usize>) {
        let mut rng = StdRng::seed_from_u64(0);
        let data: Vec<_> = lens
            .into_iter()
            .map(|len| (0..len).map(|_| rng.random::<u8>()).collect::<Vec<_>>())
            .collect();

        let out = hash(&data).await;

        let mut hasher = blake3::Hasher::new();
        for data in &data {
            hasher.update(data);
        }
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(out, expected);
    }

    // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/test_vectors/src/lib.rs.
    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    #[case(4)]
    #[case(5)]
    #[case(6)]
    #[case(7)]
    #[case(8)]
    #[case(BLOCK_LEN - 1)]
    #[case(BLOCK_LEN)]
    #[case(BLOCK_LEN + 1)]
    #[case(2 * BLOCK_LEN - 1)]
    #[case(2 * BLOCK_LEN)]
    #[case(2 * BLOCK_LEN + 1)]
    #[case(CHUNK_LEN - 1)]
    #[case(CHUNK_LEN)]
    #[case(CHUNK_LEN + 1)]
    #[case(2 * CHUNK_LEN)]
    #[case(2 * CHUNK_LEN + 1)]
    #[case(3 * CHUNK_LEN)]
    #[case(3 * CHUNK_LEN + 1)]
    #[case(4 * CHUNK_LEN)]
    #[case(4 * CHUNK_LEN + 1)]
    #[case(5 * CHUNK_LEN)]
    #[case(5 * CHUNK_LEN + 1)]
    #[case(6 * CHUNK_LEN)]
    #[case(6 * CHUNK_LEN + 1)]
    #[case(7 * CHUNK_LEN)]
    #[case(7 * CHUNK_LEN + 1)]
    #[case(8 * CHUNK_LEN)]
    #[case(8 * CHUNK_LEN + 1)]
    #[case(16 * CHUNK_LEN)] // AVX512's bandwidth
    #[case(31 * CHUNK_LEN)] // 16 + 8 + 4 + 2 + 1
    #[case(100 * CHUNK_LEN)] // subtrees larger than MAX_SIMD_DEGREE chunks
    #[tokio::test]
    async fn test_official_vectors(#[case] len: usize) {
        fn paint_test_input(buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
        }

        let mut input = vec![0; len];
        paint_test_input(&mut input);

        let test_input = if input.is_empty() {
            Vec::new()
        } else {
            vec![input.clone()]
        };

        let out = hash(&test_input).await;

        let expected: [u8; 32] = blake3::Hasher::new().update(&input).finalize().into();

        assert_eq!(out, expected);
    }
}
