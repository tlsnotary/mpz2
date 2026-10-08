//! Synchronization primitives.

mod async_mutex;
mod async_syncer;
mod barrier;
mod mutex;

pub use async_mutex::AsyncMutex;
pub use async_syncer::AsyncSyncer;
pub use barrier::{AdaptiveBarrier, BarrierResult, Waiters};
pub use mutex::{Mutex, MutexError};

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context as StdContext, Poll, Waker},
};

use futures::Future;
use serio::{IoDuplex, SinkExt, stream::IoStreamExt};
use tokio::sync::Mutex as TokioMutex;

/// The error type for [`Syncer`].
#[derive(Debug, thiserror::Error)]
#[error("sync error: {0}")]
pub struct SyncError(#[from] std::io::Error);

/// A primitive for synchronizing the order of execution across logical threads.
///
/// This is useful for when multiple different functionalities need to access
/// some shared stateful resource. In such cases, it is important that the order
/// in which this occurs is synchronized from all parties views.
///
/// [`Syncer`] employs a leader-follower coordination pattern, where the leader
/// is responsible for dictating the order of execution, and the followers
/// ensure their local execution is synchronized to it.
///
/// Every operation involves broadcasting a 4-byte ticket to all followers, so
/// be conscious of the overhead of this.
///
/// See [`Mutex`] for a higher-level primitive that can be used to obtain a lock
/// on a resource in synchronized order.
#[derive(Debug, Clone)]
pub struct Syncer(SyncerInner);

impl Syncer {
    /// Creates a new leader.
    pub fn new_leader() -> Self {
        Self(SyncerInner::Leader(Leader::default()))
    }

    /// Creates a new follower.
    pub fn new_follower() -> Self {
        Self(SyncerInner::Follower(Follower::default()))
    }

    /// Synchronizes the order of execution across logical threads.
    ///
    /// # Arguments
    ///
    /// * `io` - The I/O channel of the logical thread.
    /// * `f` - The function to execute.
    pub async fn sync<Io: IoDuplex + Unpin, F, R>(&self, io: &mut Io, f: F) -> Result<R, SyncError>
    where
        F: FnOnce() -> R + Unpin,
        R: Unpin,
    {
        match &self.0 {
            SyncerInner::Leader(leader) => leader.sync(io, f).await,
            SyncerInner::Follower(follower) => follower.sync(io, f).await,
        }
    }
}

#[derive(Debug, Clone)]
enum SyncerInner {
    Leader(Leader),
    Follower(Follower),
}

#[derive(Debug, Default, Clone)]
struct Leader {
    tick: Arc<TokioMutex<Ticket>>,
}

impl Leader {
    async fn sync<Io: IoDuplex + Unpin, F, R>(&self, io: &mut Io, f: F) -> Result<R, SyncError>
    where
        F: FnOnce() -> R + Unpin,
        R: Unpin,
    {
        let mut tick_lock = self.tick.lock().await;
        io.send(tick_lock.increment_in_place()).await?;
        let output = f();
        drop(tick_lock);

        Ok(output)
    }
}

#[derive(Debug, Default, Clone)]
struct Follower {
    queue: Arc<StdMutex<Queue>>,
}

impl Follower {
    async fn sync<Io: IoDuplex + Unpin, F, R>(&self, io: &mut Io, f: F) -> Result<R, SyncError>
    where
        F: FnOnce() -> R + Unpin,
        R: Unpin,
    {
        let tick = io.expect_next().await?;
        Ok(Wait::new(&self.queue, tick, f).await)
    }
}

#[derive(Debug, Default)]
struct Queue {
    // The current ticket.
    tick: Ticket,
    // Tasks waiting for their ticket to be accepted.
    waiting: HashMap<Ticket, Waker>,
}

impl Queue {
    // Wakes up the next waiting task.
    fn wake_next(&mut self) {
        if let Some(waker) = self.waiting.remove(&self.tick) {
            waker.wake();
        }
    }
}

#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
struct Wait<'a, F> {
    queue: &'a StdMutex<Queue>,
    tick: Ticket,
    f: Option<F>,
}

impl<'a, F> Wait<'a, F> {
    fn new(queue: &'a StdMutex<Queue>, tick: Ticket, f: F) -> Self {
        Self {
            queue,
            tick,
            f: Some(f),
        }
    }
}

impl<F, R> Future for Wait<'_, F>
where
    F: FnOnce() -> R + Unpin,
    R: Unpin,
{
    type Output = R;

    fn poll(mut self: Pin<&mut Self>, cx: &mut StdContext<'_>) -> Poll<Self::Output> {
        let mut queue_lock = self.queue.lock().unwrap();
        if queue_lock.tick == self.tick {
            let f = self
                .f
                .take()
                .expect("future should not be polled after completion");
            let output = f();
            queue_lock.tick.increment_in_place();
            queue_lock.wake_next();
            Poll::Ready(output)
        } else {
            queue_lock.waiting.insert(self.tick, cx.waker().clone());
            Poll::Pending
        }
    }
}

/// A ticket for [`Syncer`].
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Ticket(u32);

impl Ticket {
    /// Increments the ticket in place and returns the original value.
    fn increment_in_place(&mut self) -> Self {
        let current = self.0;
        // We should be able to wrap around without worry. This should only
        // corrupt synchronization if there are more than 2^32 - 1 pending ops.
        // In which case, give your head a shake.
        self.0 = self.0.wrapping_add(1);
        Self(current)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::MutexGuard;

    use futures::{executor::block_on, poll};
    use serio::channel::duplex;

    use super::*;

    #[test]
    fn test_syncer() {
        let (mut io_0a, mut io_0b) = duplex(1);
        let (mut io_1a, mut io_1b) = duplex(1);
        let (mut io_2a, mut io_2b) = duplex(1);

        let syncer_a = Syncer::new_leader();
        let syncer_b = Syncer::new_follower();

        let log_a = Arc::new(StdMutex::new(Vec::new()));
        let log_b = Arc::new(StdMutex::new(Vec::new()));

        block_on(async {
            syncer_a
                .sync(&mut io_0a, || {
                    let mut log = log_a.lock().unwrap();
                    log.push(0);
                })
                .await
                .unwrap();
            syncer_a
                .sync(&mut io_1a, || {
                    let mut log = log_a.lock().unwrap();
                    log.push(1);
                })
                .await
                .unwrap();
            syncer_a
                .sync(&mut io_2a, || {
                    let mut log = log_a.lock().unwrap();
                    log.push(2);
                })
                .await
                .unwrap();
        });

        let mut fut_a = Box::pin(syncer_b.sync(&mut io_2b, || {
            let mut log = log_b.lock().unwrap();
            log.push(2);
        }));

        let mut fut_b = Box::pin(syncer_b.sync(&mut io_0b, || {
            let mut log = log_b.lock().unwrap();
            log.push(0);
        }));

        let mut fut_c = Box::pin(syncer_b.sync(&mut io_1b, || {
            let mut log = log_b.lock().unwrap();
            log.push(1);
        }));

        block_on(async move {
            // Poll out of order.
            assert!(poll!(&mut fut_a).is_pending());
            assert!(poll!(&mut fut_c).is_pending());
            assert!(poll!(&mut fut_b).is_ready());
            assert!(poll!(&mut fut_c).is_ready());
            assert!(poll!(&mut fut_a).is_ready());
        });

        let log_a = Arc::into_inner(log_a).unwrap().into_inner().unwrap();
        let log_b = Arc::into_inner(log_b).unwrap().into_inner().unwrap();

        assert_eq!(log_a, log_b);
    }

    #[test]
    fn test_syncer_is_send() {
        let (mut io, _) = duplex(1);
        let syncer = Syncer::new_leader();

        fn is_send<T: Send>(_: T) {}

        fn closure_return_not_send<'a>() -> impl FnOnce() -> MutexGuard<'a, ()> {
            || todo!()
        }

        // The future should be send even if the type returned by the closure is
        // not.
        is_send(syncer.sync(&mut io, closure_return_not_send()));
    }
}
