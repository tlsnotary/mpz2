//! Async thread pool.
//!
//! A [`ThreadPool`] is a shared, [`Clone`]able handle to a pool of worker
//! threads that run async tasks. Build a dedicated pool with
//! [`ThreadPool::builder`], or use the process-wide [`ThreadPool::global`]
//! pool.

use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use async_task::{Runnable, Task};
use crossbeam_deque::{Injector, Steal, Stealer, Worker};
use crossbeam_utils::sync::{Parker, Unparker};

/// A shared handle to a thread pool.
///
/// `ThreadPool` is cheap to clone — clones share the same underlying pool.
/// When the last `ThreadPool` handle is dropped, the pool is shut down.
#[derive(Clone)]
pub struct ThreadPool {
    inner: Arc<Inner>,
    // Holding a guard alongside the inner Arc lets us distinguish "last user
    // handle dropped" from "last worker reference dropped". When the final
    // guard drops, the pool is shut down; workers then exit and release their
    // own `inner` refs.
    _guard: Arc<Guard>,
}

impl std::fmt::Debug for ThreadPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadPool")
            .field("num_threads", &self.inner.workers.len())
            .field("is_shutdown", &self.is_shutdown())
            .finish_non_exhaustive()
    }
}

struct Guard {
    inner: Arc<Inner>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.inner.shutdown();
    }
}

struct WorkerState {
    unparker: Unparker,
    parked: AtomicBool,
}

struct Inner {
    injector: Injector<Runnable>,
    stealers: Vec<Stealer<Runnable>>,
    workers: Box<[WorkerState]>,
    shutdown: AtomicBool,
}

impl Inner {
    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);

        // Drain the injector before unparking workers. Any push that races
        // with this drain is handled by the shutdown check in the schedule
        // callback (see `spawn_on`), which drops the runnable.
        loop {
            match self.injector.steal() {
                Steal::Success(_) => continue,
                Steal::Empty => break,
                Steal::Retry => continue,
            }
        }

        for w in self.workers.iter() {
            w.unparker.unpark();
        }
    }
}

/// A worker spawn callback.
///
/// Receives a worker entry-point and dispatches it on a thread (or
/// platform-equivalent, e.g. `web_spawn::spawn` on wasm).
pub type SpawnFn =
    Box<dyn Fn(Box<dyn FnOnce() + Send + 'static>) -> Result<(), std::io::Error> + Send + Sync>;

/// Builder for [`ThreadPool`].
pub struct ThreadPoolBuilder {
    num_threads: usize,
    spawn: SpawnFn,
}

impl std::fmt::Debug for ThreadPoolBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadPoolBuilder")
            .field("num_threads", &self.num_threads)
            .finish_non_exhaustive()
    }
}

impl Default for ThreadPoolBuilder {
    fn default() -> Self {
        Self {
            num_threads: default_num_threads(),
            spawn: Box::new(default_spawn),
        }
    }
}

fn default_num_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
}

fn default_spawn(f: Box<dyn FnOnce() + Send + 'static>) -> Result<(), std::io::Error> {
    std::thread::Builder::new()
        .name("mpz-pool-worker".to_string())
        .spawn(f)
        .map(drop)
}

impl ThreadPoolBuilder {
    /// Sets the number of worker threads.
    pub fn num_threads(mut self, n: usize) -> Self {
        self.num_threads = n;
        self
    }

    /// Sets a custom worker spawn callback.
    pub fn spawn<F>(mut self, spawn: F) -> Self
    where
        F: Fn(Box<dyn FnOnce() + Send + 'static>) -> Result<(), std::io::Error>
            + Send
            + Sync
            + 'static,
    {
        self.spawn = Box::new(spawn);
        self
    }

    /// Builds the pool.
    ///
    /// Returns an error if the [spawn callback](Self::spawn) fails to start a
    /// worker.
    pub fn build(self) -> Result<ThreadPool, ThreadPoolBuildError> {
        ThreadPool::new(self.num_threads, &self.spawn)
    }

    /// Builds the pool and installs it as the process-wide global pool, the
    /// one returned by [`ThreadPool::global`].
    ///
    /// Returns an error if the global pool has already been initialized.
    pub fn build_global(self) -> Result<(), ThreadPoolBuildError> {
        if GLOBAL_POOL.get().is_some() {
            return Err(ThreadPoolBuildError::AlreadyInitialized);
        }
        let pool = self.build()?;
        GLOBAL_POOL
            .set(pool)
            .map_err(|_| ThreadPoolBuildError::AlreadyInitialized)
    }
}

/// Errors that can occur while building a [`ThreadPool`].
#[derive(Debug, thiserror::Error)]
pub enum ThreadPoolBuildError {
    /// The process-wide global pool has already been initialized.
    #[error("global thread pool is already initialized")]
    AlreadyInitialized,
    /// A worker thread could not be started.
    #[error("failed to start a worker thread")]
    Spawn(#[source] std::io::Error),
}

/// Process-wide global pool, initialized at most once.
static GLOBAL_POOL: OnceLock<ThreadPool> = OnceLock::new();

impl ThreadPool {
    /// Creates a new builder.
    pub fn builder() -> ThreadPoolBuilder {
        ThreadPoolBuilder::default()
    }

    /// Returns a handle to the process-wide global pool.
    ///
    /// The pool is initialized with default settings on the first call. The
    /// global pool is never shut down implicitly.
    ///
    /// Panics if the default pool fails to build. Use [`try_global`] for a
    /// fallible variant — useful on platforms where the default spawn
    /// callback cannot start threads (e.g. wasm32).
    ///
    /// [`try_global`]: Self::try_global
    pub fn global() -> ThreadPool {
        Self::try_global().expect("default global thread pool should build")
    }

    /// Like [`global`](Self::global), but returns an error instead of
    /// panicking when the default pool cannot be built.
    pub fn try_global() -> Result<ThreadPool, ThreadPoolBuildError> {
        if let Some(pool) = GLOBAL_POOL.get() {
            return Ok(pool.clone());
        }
        let pool = ThreadPool::builder().build()?;
        // `set` returns `Err` if another thread won the init race; either way,
        // `GLOBAL_POOL.get()` is `Some` once we get here.
        let _ = GLOBAL_POOL.set(pool);
        Ok(GLOBAL_POOL
            .get()
            .expect("global pool is initialized")
            .clone())
    }

    /// Shuts down the pool.
    ///
    /// After this returns, no further tasks will be accepted, and any tasks
    /// still pending are cancelled — awaiters propagate cancellation rather
    /// than hanging.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    /// Returns `true` if the pool has been shut down.
    pub fn is_shutdown(&self) -> bool {
        self.inner.shutdown.load(Ordering::SeqCst)
    }

    fn new(num_threads: usize, spawn: &SpawnFn) -> Result<ThreadPool, ThreadPoolBuildError> {
        let injector = Injector::new();

        let worker_queues: Vec<Worker<Runnable>> =
            (0..num_threads).map(|_| Worker::new_fifo()).collect();

        let stealers: Vec<Stealer<Runnable>> = worker_queues.iter().map(|w| w.stealer()).collect();

        let parkers: Vec<Parker> = (0..num_threads).map(|_| Parker::new()).collect();
        let workers: Box<[WorkerState]> = parkers
            .iter()
            .map(|p| WorkerState {
                unparker: p.unparker().clone(),
                parked: AtomicBool::new(false),
            })
            .collect();

        let inner = Arc::new(Inner {
            injector,
            stealers,
            workers,
            shutdown: AtomicBool::new(false),
        });

        for (index, (local, parker)) in worker_queues.into_iter().zip(parkers).enumerate() {
            let worker_inner = inner.clone();
            if let Err(err) = spawn(Box::new(move || {
                worker_loop(worker_inner, local, index, parker)
            })) {
                // A spawn failed partway through. Signal shutdown so any
                // workers we already started exit, then surface the error.
                inner.shutdown();
                return Err(ThreadPoolBuildError::Spawn(err));
            }
        }

        Ok(ThreadPool {
            _guard: Arc::new(Guard {
                inner: inner.clone(),
            }),
            inner,
        })
    }
}

fn worker_loop(inner: Arc<Inner>, local: Worker<Runnable>, index: usize, parker: Parker) {
    let state = &inner.workers[index];

    let drain_local = |local: &Worker<Runnable>| {
        // Drop any runnables still sitting in this worker's local queue.
        // Dropping cancels the corresponding task so awaiters of `Task<T>`
        // see cancellation instead of hanging on a worker that has exited.
        while local.pop().is_some() {}
    };

    while !inner.shutdown.load(Ordering::Relaxed) {
        if let Some(runnable) = find_task(&inner, &local, index) {
            runnable.run();
            continue;
        }

        // Slow path: announce we're about to park, then recheck.
        //
        // The recheck after setting `parked = true` closes the race against a
        // producer that pushed before we announced (and therefore didn't see
        // us as a candidate to unpark).
        state.parked.store(true, Ordering::SeqCst);

        if let Some(runnable) = find_task(&inner, &local, index) {
            state.parked.store(false, Ordering::SeqCst);
            runnable.run();
            continue;
        }

        if inner.shutdown.load(Ordering::Relaxed) {
            state.parked.store(false, Ordering::SeqCst);
            break;
        }

        // If a producer fires between the recheck above and `park()`, the
        // `unpark` token is remembered by the parker and `park()` returns
        // immediately — no lost wakeup.
        parker.park();
        state.parked.store(false, Ordering::SeqCst);
    }

    drain_local(&local);
}

fn find_task(inner: &Inner, local: &Worker<Runnable>, index: usize) -> Option<Runnable> {
    if let Some(runnable) = local.pop() {
        return Some(runnable);
    }

    loop {
        match inner.injector.steal_batch_and_pop(local) {
            Steal::Success(runnable) => return Some(runnable),
            Steal::Empty => break,
            Steal::Retry => continue,
        }
    }

    let num_stealers = inner.stealers.len();
    for i in 1..num_stealers {
        let victim = (index + i) % num_stealers;
        loop {
            match inner.stealers[victim].steal_batch_and_pop(local) {
                Steal::Success(runnable) => return Some(runnable),
                Steal::Empty => break,
                Steal::Retry => continue,
            }
        }
    }

    None
}

/// Spawns a future on the given pool.
pub(crate) fn spawn_on<F>(pool: &ThreadPool, future: F) -> Task<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let inner = pool.inner.clone();
    let schedule = move |runnable: Runnable| {
        // After shutdown, no worker will run this. Dropping the runnable
        // cancels the task so the awaiter doesn't hang. SeqCst pairs with
        // the SeqCst store in `Inner::shutdown` to ensure that any push
        // that "loses" the race is then drained by shutdown's pass over
        // the injector.
        if inner.shutdown.load(Ordering::SeqCst) {
            drop(runnable);
            return;
        }
        inner.injector.push(runnable);
        // Scan for an idle worker and claim it for this notification. The
        // `load` is a cheap filter; the `compare_exchange` is what makes the
        // claim race-free against other concurrent producers. Stops at the
        // first claimed worker — one push, one wake.
        for w in inner.workers.iter() {
            if w.parked.load(Ordering::SeqCst)
                && w.parked
                    .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                w.unparker.unpark();
                break;
            }
        }
    };
    let (runnable, task) = async_task::spawn(future, schedule);
    runnable.schedule();
    task
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_drop_shuts_down() {
        let pool = ThreadPool::builder().num_threads(2).build().unwrap();
        let weak = Arc::downgrade(&pool.inner);
        drop(pool);
        // After the last handle is dropped, workers observe shutdown and
        // release their refs. Give them a moment to wind down.
        for _ in 0..100 {
            if weak.strong_count() == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(weak.strong_count(), 0);
    }

    #[test]
    fn test_build_global_rejects_second_call() {
        // The global pool may have been initialized by another test in this
        // binary. Either way, a subsequent `build_global` must fail.
        let _ = ThreadPool::global();
        let err = ThreadPool::builder().num_threads(1).build_global();
        assert!(err.is_err());
    }
}
