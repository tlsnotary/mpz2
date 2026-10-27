use futures::channel::oneshot;
use std::sync::{Arc, Mutex};

/// An async barrier that dynamically adjusts to the number of live instances.
///
/// A single instance will be elected as the leader, and all other instances
/// will wait for the leader to signal that it is ready to proceed.
///
/// # Limitations
///
/// The barrier may not be cloned while any instances are waiting. Doing so will
/// cause the barrier to panic.
#[derive(Debug)]
pub struct AdaptiveBarrier {
    id: usize,
    state: Arc<Mutex<State>>,
}

impl AdaptiveBarrier {
    /// Creates a new barrier.
    pub fn new() -> Self {
        let mut state = State::default();
        let id = state.register();

        Self {
            id,
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Waits until all instances of the barrier have arrived.
    ///
    /// Returns `true` if this instance has been elected as the leader.
    pub async fn wait(&mut self) -> BarrierResult {
        let recv = {
            let mut state = self.state.lock().unwrap();

            // Early return if this is the only instance.
            if state.alive == 1 {
                return BarrierResult::Leader(Waiters::empty());
            }

            if !state.is_pending() {
                state.start();
            } else {
                state.arrive();
            }

            let recv = state.wait(self.id);

            if state.is_ready() {
                state.wake_leader();
            }

            recv
        };

        match recv.await {
            Ok(result) => result,
            // The only case where this can happen is if the leader drops the
            // result, in which case we can just proceed.
            Err(_) => BarrierResult::Waiter,
        }
    }
}

impl Clone for AdaptiveBarrier {
    fn clone(&self) -> Self {
        let id = self.state.lock().unwrap().register();
        Self {
            id,
            state: self.state.clone(),
        }
    }
}

impl Default for AdaptiveBarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AdaptiveBarrier {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.deregister();
        }
    }
}

#[derive(Debug)]
struct Waiter {
    id: usize,
    sender: oneshot::Sender<BarrierResult>,
}

/// A collection of waiters waiting to be woken. Returned by
/// [`AdaptiveBarrier::wait`].
#[derive(Debug)]
pub struct Waiters {
    waiters: Vec<Waiter>,
}

impl Waiters {
    fn empty() -> Self {
        Self {
            waiters: Vec::new(),
        }
    }

    fn new(waiters: Vec<Waiter>) -> Self {
        Self { waiters }
    }

    /// Wake all waiters at the barrier.
    pub fn wake(self) {
        for Waiter { sender, .. } in self.waiters {
            _ = sender.send(BarrierResult::Waiter);
        }
    }
}

/// Result returned by [`AdaptiveBarrier::wait`].
#[derive(Debug)]
pub enum BarrierResult {
    /// The current instance was elected as the leader.
    Leader(Waiters),
    /// The current instance waited for the leader.
    Waiter,
}

impl BarrierResult {
    /// Returns `true` if the current instance was elected as the leader.
    pub fn is_leader(&self) -> bool {
        matches!(self, Self::Leader(_))
    }

    /// Proceeds past the barrier, signalling to all waiters if the current
    /// instance was elected as the leader.
    pub fn proceed(self) {
        if let Self::Leader(waiters) = self {
            waiters.wake();
        }
    }
}

#[derive(Debug, Default)]
struct State {
    /// Number of live clones.
    alive: usize,
    /// Next clone id.
    id_next: usize,

    /// Number of clones that have arrived.
    arrived: usize,
    /// Number of clones expected to arrive.
    expected: usize,

    /// Waiters for the barrier.
    waiters: Vec<Waiter>,
}

impl State {
    fn is_pending(&self) -> bool {
        self.arrived != 0
    }

    fn is_ready(&self) -> bool {
        self.arrived == self.expected
    }

    /// Registers a new clone.
    fn register(&mut self) -> usize {
        if self.is_pending() {
            panic!("attempted to clone barrier while waiting");
        }

        let id = self.id_next;

        self.id_next += 1;
        self.alive += 1;

        id
    }

    /// Deregisters a clone.
    fn deregister(&mut self) {
        self.alive -= 1;

        if self.is_pending() {
            self.expected -= 1;
        }
    }

    fn arrive(&mut self) {
        self.arrived += 1;
    }

    fn start(&mut self) {
        self.arrived = 1;
        self.expected = self.alive;
    }

    fn wait(&mut self, id: usize) -> oneshot::Receiver<BarrierResult> {
        let (sender, receiver) = oneshot::channel();
        self.waiters.push(Waiter { id, sender });
        receiver
    }

    fn wake_leader(&mut self) {
        let mut waiters = std::mem::take(&mut self.waiters);
        waiters.sort_by_key(|waiter| waiter.id);

        // Elect the waiter with the highest id as the leader.
        let leader = waiters.pop().expect("there should be at least one waiter");
        leader
            .sender
            .send(BarrierResult::Leader(Waiters::new(waiters)))
            .expect("leader should not be dropped before waking");

        self.arrived = 0;
        self.expected = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::{pin::pin, task::Poll};

    use futures::{FutureExt, poll};

    use super::*;

    #[tokio::test]
    async fn test_barrier_single_is_ready() {
        let mut barrier = AdaptiveBarrier::new();
        let fut = pin!(barrier.wait());

        let Poll::Ready(result) = poll!(fut) else {
            panic!("barrier should be ready");
        };

        assert!(result.is_leader(), "single instance should be leader");
    }

    #[tokio::test]
    async fn test_barrier() {
        let mut barrier_0 = AdaptiveBarrier::new();
        let mut barrier_1 = barrier_0.clone();

        let mut fut_0 = pin!(barrier_0.wait());
        let fut_1 = pin!(barrier_1.wait());

        assert!(
            poll!(&mut fut_0).is_pending(),
            "barrier_0 should not be ready"
        );

        let Poll::Ready(result) = poll!(fut_1) else {
            panic!("barrier_1 should be ready");
        };
        assert!(result.is_leader(), "barrier_1 should be leader");

        assert!(
            poll!(&mut fut_0).is_pending(),
            "barrier_0 should not be ready until after the leader proceeds"
        );

        result.proceed();

        let Poll::Ready(result) = poll!(fut_0) else {
            panic!("barrier_0 should be ready");
        };
        assert!(!result.is_leader(), "barrier_0 should not be leader");
    }

    #[tokio::test]
    async fn test_barrier_leader_drops_result() {
        let mut barrier_0 = AdaptiveBarrier::new();
        let mut barrier_1 = barrier_0.clone();

        let mut fut_0 = pin!(barrier_0.wait());
        let fut_1 = pin!(barrier_1.wait());

        assert!(
            poll!(&mut fut_0).is_pending(),
            "barrier_0 should not be ready"
        );

        let Poll::Ready(result) = poll!(fut_1) else {
            panic!("barrier_1 should be ready");
        };
        assert!(result.is_leader(), "barrier_1 should be leader");

        assert!(
            poll!(&mut fut_0).is_pending(),
            "barrier_0 should not be ready"
        );

        // Drop result instead of explicitly waking the waiters.
        drop(result);

        let Poll::Ready(result) = poll!(fut_0) else {
            panic!("barrier_0 should be ready");
        };
        assert!(!result.is_leader(), "barrier_0 should not be leader");
    }

    #[tokio::test]
    async fn test_barrier_multiple() {
        let mut barrier_0 = AdaptiveBarrier::new();
        let mut barrier_1 = barrier_0.clone();

        // Wait once.
        tokio::join!(
            barrier_0.wait().map(|result| result.proceed()),
            barrier_1.wait().map(|result| result.proceed())
        );

        // Wait again.
        let mut fut_0 = pin!(barrier_0.wait());
        let fut_1 = pin!(barrier_1.wait());

        assert!(
            poll!(&mut fut_0).is_pending(),
            "barrier_0 should not be ready"
        );

        let Poll::Ready(result) = poll!(fut_1) else {
            panic!("barrier_1 should be ready");
        };
        assert!(result.is_leader(), "barrier_1 should be leader");

        result.proceed();

        let Poll::Ready(result) = poll!(fut_0) else {
            panic!("barrier_0 should be ready");
        };
        assert!(!result.is_leader(), "barrier_0 should not be leader");
    }

    #[tokio::test]
    #[should_panic]
    async fn test_barrier_panic_on_clone_while_waiting() {
        let mut barrier_0 = AdaptiveBarrier::new();
        let barrier_1 = barrier_0.clone();

        let mut fut = pin!(barrier_0.wait());

        assert!(
            poll!(&mut fut).is_pending(),
            "barrier_0 should not be ready"
        );

        let _barrier = barrier_1.clone();
    }
}
