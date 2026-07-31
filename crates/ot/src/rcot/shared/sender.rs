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
    rcot::{RCOTSender, RCOTSenderOutput},
};
use tokio::sync::Mutex;

#[derive(Debug)]
struct Buffer<U> {
    /// Number of OTs which have been allocated but not yet setup.
    ///
    /// Reset to zero as soon as a flush fulfills the allocation, so that it
    /// only ever counts *outstanding* work.
    count: usize,
    keys: Vec<U>,
}

impl<U> Buffer<U> {
    fn new(count: usize) -> Self {
        Self {
            count,
            keys: Vec::with_capacity(count),
        }
    }
}

#[derive(Debug)]
struct State<U> {
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
    buffers: HashMap<usize, Buffer<U>>,
}

impl<U> State<U> {
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
struct Queued<U> {
    count: usize,
    sender: Sender<RCOTSenderOutput<U>>,
}

/// Shared RCOT sender.
#[derive(Debug)]
pub struct SharedRCOTSender<T, U> {
    id: usize,
    transfer_id: TransferId,
    inner: Arc<Mutex<T>>,
    barrier: AdaptiveBarrier,
    state: Arc<StdMutex<State<U>>>,
    delta: U,
    keys: Vec<U>,
    queue: VecDeque<Queued<U>>,
}

impl<T, U> SharedRCOTSender<T, U>
where
    T: RCOTSender<U>,
    U: Copy + Send,
{
    /// Creates a new shared RCOT sender.
    pub fn new(inner: T) -> Self {
        let delta = inner.delta();
        let inner = Arc::new(Mutex::new(inner));
        let barrier = AdaptiveBarrier::new();

        let mut state = State::new();
        let id = state.register();

        Self {
            id,
            transfer_id: TransferId::default(),
            inner: inner.clone(),
            barrier: barrier.clone(),
            state: Arc::new(StdMutex::new(state)),
            delta,
            keys: Vec::new(),
            queue: VecDeque::new(),
        }
    }
}

impl<T, U> Clone for SharedRCOTSender<T, U>
where
    U: Clone,
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
            delta: self.delta.clone(),
            keys: Vec::new(),
            queue: VecDeque::new(),
        }
    }
}

impl<T, U> RCOTSender<U> for SharedRCOTSender<T, U>
where
    T: RCOTSender<U>,
    U: Copy + Send,
{
    type Error = SharedRCOTSenderError;
    type Future = MaybeDone<RCOTSenderOutput<U>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if count == 0 {
            return Ok(());
        }

        let mut state = self.state.lock().unwrap();

        state.alloc += count;

        if let Some(buffer) = state.buffers.get_mut(&self.id) {
            buffer.count += count;
            buffer.keys.reserve(count);
        } else {
            state.buffers.insert(self.id, Buffer::new(count));
        }

        Ok(())
    }

    fn available(&self) -> usize {
        self.keys.len()
    }

    fn delta(&self) -> U {
        self.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<U>, Self::Error> {
        if self.available() < count {
            return Err(ErrorRepr::InsufficientSetup {
                expected: count,
                actual: self.available(),
            }
            .into());
        }

        let keys = self.keys.split_off(self.keys.len() - count);

        Ok(RCOTSenderOutput {
            id: self.transfer_id.next(),
            keys,
        })
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.available() >= count {
            let output = self.try_send_rcot(count)?;
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
impl<T, U> Flush for SharedRCOTSender<T, U>
where
    T: RCOTSender<U> + Flush + Send,
    U: Copy + Send,
{
    type Error = SharedRCOTSenderError;

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
                for Buffer { count, .. } in state.buffers.values() {
                    if *count > 0 {
                        inner.alloc(*count).map_err(SharedRCOTSenderError::inner)?;
                    }
                }
            }

            inner
                .flush(ctx)
                .await
                .map_err(SharedRCOTSenderError::inner)?;

            let state = &mut (*self.state.lock().unwrap());
            let mut buffers = state.buffers.iter_mut().collect::<Vec<_>>();
            buffers.sort_by_key(|(id, _)| *id);

            for (_, buffer) in buffers {
                if buffer.count == 0 {
                    continue;
                }

                let keys = inner
                    .try_send_rcot(buffer.count)
                    .map_err(SharedRCOTSenderError::inner)?
                    .keys;

                // The allocation is fulfilled. It must be cleared here rather
                // than when the instance picks the keys up: until then the
                // buffer is still present, and a non-zero count would make
                // instances which are already done believe another flush is
                // required.
                buffer.count = 0;

                // Optimization: avoid expensive copying of `keys` potentially
                // containing millions of elements.
                if keys.len() > buffer.keys.len() {
                    let old_keys = std::mem::replace(&mut buffer.keys, keys);
                    buffer.keys.extend_from_slice(&old_keys);
                } else {
                    buffer.keys.extend_from_slice(&keys);
                }
            }
        }
        barrier_result.proceed();

        {
            let mut state = self.state.lock().unwrap();
            if let Some(buffer) = state.buffers.get_mut(&self.id) {
                let keys = take(&mut buffer.keys);

                // Only discard the buffer if it has no allocation outstanding,
                // otherwise an allocation made during this flush would be lost.
                if buffer.count == 0 {
                    state.buffers.remove(&self.id);
                }

                // Optimization: avoid expensive copying of `keys` potentially
                // containing millions of elements.
                if keys.len() > self.keys.len() {
                    let old_keys = std::mem::replace(&mut self.keys, keys);
                    self.keys.extend_from_slice(&old_keys);
                } else {
                    self.keys.extend_from_slice(&keys);
                }
            }
        }

        for queued in take(&mut self.queue) {
            let output = self.try_send_rcot(queued.count)?;
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
        let mut state = State::<()>::new();
        let id = state.register();

        state.buffers.insert(id, Buffer::new(8));
        assert!(state.wants_flush());

        // The flush fulfilled the allocation, but the instance has not picked
        // its keys up yet, so the buffer is still in the map.
        state.buffers.get_mut(&id).unwrap().count = 0;
        assert!(!state.wants_flush());
    }

    /// Once one instance has committed to a flush, every other instance must
    /// join it, even if the allocation which triggered it is already fulfilled
    /// by the time they check.
    #[test]
    fn test_enter_flush_is_collective() {
        let mut state = State::<()>::new();
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

/// Error for [`SharedRCOTSender`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SharedRCOTSenderError(#[from] ErrorRepr);

impl SharedRCOTSenderError {
    fn inner<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Sender(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("shared RCOT sender error: ")]
enum ErrorRepr {
    #[error("inner sender error: {0}")]
    Sender(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("insufficient RCOTs setup: expected {expected}, actual {actual}")]
    InsufficientSetup { expected: usize, actual: usize },
}
