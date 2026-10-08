use std::sync::Arc;

use rand::RngExt;
use tokio::sync::{Mutex, OwnedMutexGuard};

use mpz_core::{Block, bitvec::BitVec, prg::Prg};
use mpz_memory_core::{
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
    binary::Binary,
    correlated::{Delta, Key, KeyStore, KeyStoreError},
    store::{BitStore, StoreError},
};
use mpz_ot_core::cot::COTSender;

use crate::{
    FlushView,
    store::{EvaluatorFlush, GarblerFlush, MacProof},
    view::{View, ViewError},
};

type Error = GarblerStoreError;
type Result<T> = core::result::Result<T, Error>;

/// Garbler memory store.
#[derive(Debug)]
pub struct GarblerStore<COT> {
    cot: Arc<Mutex<COT>>,
    prg: Prg,
    key_store: KeyStore,
    data_store: BitStore,
    view: View,
    buffer_decode: Vec<DecodeOp<BitVec>>,
    // Whether the store is waiting for a flush.
    pending: bool,
}

impl<COT> GarblerStore<COT> {
    /// Creates a new garbler store.
    pub fn new(seed: [u8; 16], delta: Delta, cot: COT) -> Self {
        Self {
            cot: Arc::new(Mutex::new(cot)),
            prg: Prg::new_with_seed(seed),
            key_store: KeyStore::new(delta),
            data_store: BitStore::new(),
            view: View::new_garbler(),
            buffer_decode: Vec::new(),
            pending: false,
        }
    }

    /// Returns delta.
    pub fn delta(&self) -> &Delta {
        self.key_store.delta()
    }

    /// Returns a lock on the COT sender.
    pub fn acquire_cot(&self) -> OwnedMutexGuard<COT> {
        Mutex::try_lock_owned(self.cot.clone()).unwrap()
    }

    /// Returns the COT sender.
    ///
    /// # Panics
    ///
    /// Panics if a lock to the sender is still held.
    pub fn into_inner(self) -> COT {
        Arc::try_unwrap(self.cot)
            .map_err(|_| ())
            .expect("sender lock should be dropped")
            .into_inner()
    }

    /// Returns whether all the keys are set.
    pub fn is_set_keys(&self, slice: Slice) -> bool {
        self.key_store.is_set(slice)
    }

    /// Returns whether the slice is committed.
    pub fn is_committed(&self, slice: Slice) -> bool {
        self.view.is_committed(slice.to_range())
    }

    /// Returns keys if they are set.
    ///
    /// # Security
    ///
    /// **Never** use this method to transfer MACs to the evaluator.
    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.key_store.try_get(slice).map_err(Error::from)
    }

    /// Allocates uninitialized memory for output values.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.view.alloc_output(len);
        self.key_store.alloc(len);
        self.data_store.alloc(len)
    }

    /// Sets the keys for output data.
    pub fn set_output(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.key_store.try_set(slice, keys)?;
        self.view.set_preprocessed(slice.to_range())?;

        Ok(())
    }

    /// Marks an output as executed.
    ///
    /// This indicates that both parties have *executed* the call which produces
    /// this output.
    pub fn mark_output_complete(&mut self, slice: Slice) -> Result<()> {
        self.view.set_output(slice.to_range()).map_err(Error::from)
    }

    /// Returns `true` if the store wants to flush.
    pub fn wants_flush(&self) -> bool {
        self.view.wants_flush()
    }

    /// Flushes decode operations.
    fn flush_decode(&mut self) -> Result<()> {
        for mut op in self
            .buffer_decode
            .extract_if(.., |op| self.data_store.is_set(op.slice))
        {
            let data = self.data_store.try_get(op.slice)?;
            op.send(data.to_bitvec())?;
        }

        Ok(())
    }
}

impl<COT> GarblerStore<COT>
where
    COT: COTSender<Block>,
{
    /// Returns the flush view.
    pub fn flush_view(&self) -> &FlushView {
        self.view.flush()
    }

    /// Sends a flush to the evaluator.
    ///
    /// This queues any necessary COTs.
    pub fn send_flush(&mut self) -> Result<GarblerFlush> {
        if self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let view = self.view.flush().clone();

        // Collect MACs.
        let mut macs = Vec::with_capacity(view.macs.len());
        for range in view.macs.iter() {
            let slice = Slice::from_range_unchecked(range);
            let data = self.data_store.try_get(slice)?;
            macs.extend(self.key_store.authenticate(slice, data)?);
        }

        // Send keys for OT.
        if !view.ot.is_empty() {
            let mut keys = Vec::with_capacity(view.ot.len());
            for range in view.ot.iter() {
                let slice = Slice::from_range_unchecked(range);
                keys.extend_from_slice(self.key_store.oblivious_transfer(slice)?);
            }

            // Queue COT, we don't need the output here.
            _ = self
                .cot
                .try_lock()
                .unwrap()
                .queue_send_cot(Key::as_blocks(&keys))
                .map_err(Error::cot)?;
        }

        // Collect key bits.
        let mut key_bits = BitVec::with_capacity(view.decode_info.len());
        for range in view.decode_info.iter() {
            let slice = Slice::from_range_unchecked(range);
            key_bits.extend(self.key_store.try_get_bits(slice)?);
        }

        // Collect MAC commitments.
        let mut mac_commitments = Vec::with_capacity(view.decode_info.len());
        for range in view.decode_info.iter() {
            let slice = Slice::from_range_unchecked(range);
            mac_commitments.extend(self.key_store.commit(slice)?);
        }

        let flush = GarblerFlush {
            macs,
            key_bits,
            mac_commitments,
        };

        self.pending = true;

        Ok(flush)
    }

    /// Receives a flush from the evaluator.
    pub fn receive_flush(&mut self, flush: EvaluatorFlush) -> Result<()> {
        if !self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let EvaluatorFlush { mac_proof } = flush;

        // Verify MACs and store the data.
        if let Some(MacProof { mut bits, proof }) = mac_proof {
            if bits.len() != self.view.flush().decode.len() {
                return Err(ErrorRepr::IncorrectMacCount {
                    expected: self.view.flush().decode.len(),
                    actual: bits.len(),
                }
                .into());
            }

            self.key_store
                .verify(&self.view.flush().decode, &mut bits, proof)?;

            let mut i = 0;
            for range in self.view.flush().decode.iter() {
                let slice = Slice::from_range_unchecked(range);
                self.data_store.try_set(slice, &bits[i..i + slice.len()])?;
                i += slice.len();
            }
        }

        self.view.complete_flush();
        self.flush_decode()?;
        self.pending = false;

        Ok(())
    }
}

impl<COT> Memory<Binary> for GarblerStore<COT> {
    type Error = Error;

    fn is_alloc_raw(&self, slice: Slice) -> bool {
        self.view.is_alloc(slice.to_range())
    }

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        let keys = (0..size).map(|_| self.prg.random()).collect::<Vec<_>>();
        self.view.alloc_input(size);
        self.key_store.alloc_with(&keys);
        let slice = self.data_store.alloc(size);

        Ok(slice)
    }

    fn is_assigned_raw(&self, slice: Slice) -> bool {
        self.data_store.is_set(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        self.view.assign(slice.to_range())?;
        self.data_store.try_set(slice, &data)?;

        Ok(())
    }

    fn is_committed_raw(&self, slice: Slice) -> bool {
        self.view.is_committed(slice.to_range())
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.commit(slice.to_range()).map_err(Error::from)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        Ok(self.data_store.get(slice).map(|data| data.to_bitvec()))
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.view.decode(slice.to_range())?;

        let (fut, mut op) = DecodeFuture::new(slice);
        // If data is already available, send it immediately.
        if let Ok(data) = self.data_store.try_get(slice) {
            op.send(data.to_bitvec())?;
        } else {
            self.buffer_decode.push(op);
        }

        Ok(fut)
    }
}

impl<COT> ViewTrait<Binary> for GarblerStore<COT>
where
    COT: COTSender<Block>,
{
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.mark_public_raw(slice).map_err(Error::from)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.mark_private_raw(slice).map_err(Error::from)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        // Allocate COTs for blind data.
        self.cot
            .try_lock()
            .unwrap()
            .alloc(slice.len())
            .map_err(Error::cot)?;

        self.view.mark_blind_raw(slice).map_err(Error::from)
    }
}

/// Error for [`GarblerStore`].
#[derive(Debug, thiserror::Error)]
#[error("garbler store error: {}", .0)]
pub struct GarblerStoreError(#[from] ErrorRepr);

impl GarblerStoreError {
    fn cot<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Cot(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("cot error: {0}")]
    Cot(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    KeyStore(KeyStoreError),
    #[error(transparent)]
    Store(StoreError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    View(#[from] ViewError),
    #[error("evaluator sent incorrect number of MAC bits, expected={expected}, actual={actual}")]
    IncorrectMacCount { expected: usize, actual: usize },
    #[error("store was not expecting a flush")]
    UnexpectedFlush,
}

impl From<KeyStoreError> for GarblerStoreError {
    fn from(err: KeyStoreError) -> Self {
        Self(ErrorRepr::KeyStore(err))
    }
}

impl From<StoreError> for GarblerStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<DecodeError> for GarblerStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}

impl From<ViewError> for GarblerStoreError {
    fn from(err: ViewError) -> Self {
        Self(ErrorRepr::View(err))
    }
}
