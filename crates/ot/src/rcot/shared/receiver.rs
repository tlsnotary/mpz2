use std::{
    collections::{HashMap, VecDeque},
    mem::take,
    sync::{Arc, Mutex as StdMutex},
};

use async_trait::async_trait;
use mpz_common::{
    Context, Flush,
    future::{MaybeDone, Sender, new_output},
    sync::AdaptiveBarrier,
};
use mpz_ot_core::{
    TransferId,
    rcot::{RCOTReceiver, RCOTReceiverOutput},
};
use tokio::sync::Mutex;

#[derive(Debug)]
struct Buffer<U, V> {
    /// Number of OTs which have been allocated but not yet setup.
    ///
    /// Reset to zero as soon as a flush fulfills the allocation, so that it
    /// only ever counts *outstanding* work.
    count: usize,
    inputs: Vec<U>,
    macs: Vec<V>,
}

impl<U, V> Buffer<U, V> {
    fn new(count: usize) -> Self {
        Self {
            count,
            inputs: Vec::with_capacity(count),
            macs: Vec::with_capacity(count),
        }
    }
}

#[derive(Debug)]
struct State<U, V> {
    id_next: usize,
    alloc: usize,
    /// Whether a flush is currently in progress.
    ///
    /// A flush is a collective operation: the barrier only releases once
    /// *every* live instance has arrived. Instances decide independently
    /// whether to flush, so once one of them commits to a flush all the
    /// others must follow, even if the allocation which triggered it has
    /// been fulfilled by the time they check.
    flushing: bool,
    buffers: HashMap<usize, Buffer<U, V>>,
}

impl<U, V> State<U, V> {
    fn new() -> Self {
        Self {
            id_next: 0,
            alloc: 0,
            flushing: false,
            buffers: HashMap::new(),
        }
    }

    fn register(&mut self) -> usize {
        let id = self.id_next;
        self.id_next += 1;
        id
    }

    /// Returns `true` if any instance has an allocation which has not been
    /// setup yet.
    fn wants_flush(&self) -> bool {
        self.buffers.values().any(|buffer| buffer.count > 0)
    }

    /// Returns `true` if this instance must participate in a flush, marking a
    /// flush as in progress if one is not already.
    fn enter_flush(&mut self) -> bool {
        if !self.flushing {
            if !self.wants_flush() {
                return false;
            }

            self.flushing = true;
        }

        true
    }
}

#[derive(Debug)]
struct Queued<U, V> {
    count: usize,
    sender: Sender<RCOTReceiverOutput<U, V>>,
}

/// Shared RCOT receiver.
#[derive(Debug)]
pub struct SharedRCOTReceiver<T, U, V> {
    id: usize,
    transfer_id: TransferId,
    inner: Arc<Mutex<T>>,
    barrier: AdaptiveBarrier,
    state: Arc<StdMutex<State<U, V>>>,
    inputs: Vec<U>,
    macs: Vec<V>,
    queue: VecDeque<Queued<U, V>>,
}

impl<T, U, V> SharedRCOTReceiver<T, U, V>
where
    T: RCOTReceiver<U, V>,
    U: Copy + Send,
    V: Copy + Send,
{
    /// Creates a new shared RCOT receiver.
    pub fn new(inner: T) -> Self {
        let inner = Arc::new(Mutex::new(inner));
        let barrier = AdaptiveBarrier::new();
        let mut state = State::new();
        let id = state.register();

        Self {
            id,
            transfer_id: TransferId::default(),
            inner,
            barrier,
            state: Arc::new(StdMutex::new(state)),
            inputs: Vec::new(),
            macs: Vec::new(),
            queue: VecDeque::new(),
        }
    }
}

impl<T, U, V> Clone for SharedRCOTReceiver<T, U, V>
where
    U: Copy + Send,
    V: Copy + Send,
{
    fn clone(&self) -> Self {
        let mut state = self.state.lock().unwrap();
        let id = state.register();

        Self {
            id,
            transfer_id: TransferId::default(),
            inner: self.inner.clone(),
            barrier: self.barrier.clone(),
            state: self.state.clone(),
            inputs: Vec::new(),
            macs: Vec::new(),
            queue: VecDeque::new(),
        }
    }
}

impl<T, U, V> RCOTReceiver<U, V> for SharedRCOTReceiver<T, U, V>
where
    T: RCOTReceiver<U, V>,
    U: Copy + Send,
    V: Copy + Send,
{
    type Error = SharedRCOTReceiverError;
    type Future = MaybeDone<RCOTReceiverOutput<U, V>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if count == 0 {
            return Ok(());
        }

        let mut state = self.state.lock().unwrap();

        state.alloc += count;

        if let Some(buffer) = state.buffers.get_mut(&self.id) {
            buffer.count += count;
            buffer.inputs.reserve(count);
            buffer.macs.reserve(count);
        } else {
            state.buffers.insert(self.id, Buffer::new(count));
        }

        Ok(())
    }

    fn available(&self) -> usize {
        self.macs.len()
    }

    fn try_recv_rcot(&mut self, count: usize) -> Result<RCOTReceiverOutput<U, V>, Self::Error> {
        if self.available() < count {
            return Err(ErrorRepr::InsufficientSetup {
                expected: count,
                actual: self.available(),
            }
            .into());
        }

        let inputs = self.inputs.split_off(self.inputs.len() - count);
        let macs = self.macs.split_off(self.macs.len() - count);

        Ok(RCOTReceiverOutput {
            id: self.transfer_id.next(),
            choices: inputs,
            msgs: macs,
        })
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.available() >= count {
            let output = self.try_recv_rcot(count)?;
            let (sender, recv) = new_output();
            sender.send(output);

            Ok(recv)
        } else {
            let (sender, recv) = new_output();

            self.queue.push_back(Queued { count, sender });

            Ok(recv)
        }
    }
}

#[async_trait]
impl<T, U, V> Flush for SharedRCOTReceiver<T, U, V>
where
    T: RCOTReceiver<U, V> + Flush + Send,
    U: Copy + Send,
    V: Copy + Send,
{
    type Error = SharedRCOTReceiverError;

    fn wants_flush(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.flushing || state.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        if !self.state.lock().unwrap().enter_flush() {
            return Ok(());
        }

        let barrier_result = self.barrier.wait().await;

        if barrier_result.is_leader() {
            let mut inner = self.inner.lock().await;

            {
                let mut state = self.state.lock().unwrap();
                // Every instance is parked at the barrier until `proceed`
                // below, so none of them can observe the flag in between and
                // clearing it here also covers the error paths.
                state.flushing = false;
                for buffer in state.buffers.values() {
                    if buffer.count > 0 {
                        inner
                            .alloc(buffer.count)
                            .map_err(SharedRCOTReceiverError::inner)?;
                    }
                }
            }

            inner
                .flush(ctx)
                .await
                .map_err(SharedRCOTReceiverError::inner)?;

            let state = &mut (*self.state.lock().unwrap());
            let mut buffers = state.buffers.iter_mut().collect::<Vec<_>>();
            buffers.sort_by_key(|(id, _)| *id);

            for (_, buffer) in buffers {
                if buffer.count == 0 {
                    continue;
                }

                let output = inner
                    .try_recv_rcot(buffer.count)
                    .map_err(SharedRCOTReceiverError::inner)?;

                // The allocation is fulfilled. It must be cleared here rather
                // than when the instance picks the OTs up: until then the
                // buffer is still present, and a non-zero count would make
                // instances which are already done believe another flush is
                // required.
                buffer.count = 0;

                // Optimization: avoid expensive copying of `choices` and
                // `msgs` potentially containing millions of elements.
                if output.choices.len() > buffer.inputs.len() {
                    let old_inputs = std::mem::replace(&mut buffer.inputs, output.choices);
                    let old_macs = std::mem::replace(&mut buffer.macs, output.msgs);
                    buffer.inputs.extend_from_slice(&old_inputs);
                    buffer.macs.extend_from_slice(&old_macs);
                } else {
                    buffer.inputs.extend_from_slice(&output.choices);
                    buffer.macs.extend_from_slice(&output.msgs);
                }
            }
        }
        barrier_result.proceed();

        {
            let mut state = self.state.lock().unwrap();
            if let Some(buffer) = state.buffers.get_mut(&self.id) {
                let inputs = take(&mut buffer.inputs);
                let macs = take(&mut buffer.macs);

                // Only discard the buffer if it has no allocation outstanding,
                // otherwise an allocation made during this flush would be lost.
                if buffer.count == 0 {
                    state.buffers.remove(&self.id);
                }

                // Optimization: avoid expensive copying of `inputs` and
                // `macs` potentially containing millions of elements.
                if inputs.len() > self.inputs.len() {
                    let old_inputs = std::mem::replace(&mut self.inputs, inputs);
                    let old_macs = std::mem::replace(&mut self.macs, macs);
                    self.inputs.extend_from_slice(&old_inputs);
                    self.macs.extend_from_slice(&old_macs);
                } else {
                    self.inputs.extend_from_slice(&inputs);
                    self.macs.extend_from_slice(&macs);
                }
            }
        }

        for queued in take(&mut self.queue) {
            let output = self.try_recv_rcot(queued.count)?;
            queued.sender.send(output);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A buffer which is still present but has no outstanding allocation must
    /// not keep asking for flushes, otherwise instances which have already
    /// finished are pulled back into a barrier nobody else will join.
    #[test]
    fn test_fulfilled_buffer_does_not_want_flush() {
        let mut state = State::<(), ()>::new();
        let id = state.register();

        state.buffers.insert(id, Buffer::new(8));
        assert!(state.wants_flush());

        // The flush fulfilled the allocation, but the instance has not picked
        // its OTs up yet, so the buffer is still in the map.
        state.buffers.get_mut(&id).unwrap().count = 0;
        assert!(!state.wants_flush());
    }

    /// Once one instance has committed to a flush, every other instance must
    /// join it, even if the allocation which triggered it is already fulfilled
    /// by the time they check.
    #[test]
    fn test_enter_flush_is_collective() {
        let mut state = State::<(), ()>::new();
        let first = state.register();
        let second = state.register();

        assert!(!state.enter_flush());

        state.buffers.insert(first, Buffer::new(8));
        assert!(state.enter_flush());

        state.buffers.get_mut(&first).unwrap().count = 0;
        assert!(state.enter_flush());

        state.flushing = false;
        state.buffers.insert(second, Buffer::new(0));
        assert!(!state.enter_flush());
    }
}

/// Error for [`SharedRCOTReceiver`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SharedRCOTReceiverError(#[from] ErrorRepr);

impl SharedRCOTReceiverError {
    fn inner<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Receiver(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("shared RCOT receiver error: ")]
enum ErrorRepr {
    #[error("inner receiver error: {0}")]
    Receiver(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("insufficient RCOTs setup: expected {expected}, actual {actual}")]
    InsufficientSetup { expected: usize, actual: usize },
}
