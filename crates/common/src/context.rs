//! Execution context.

#[cfg(any(test, feature = "test-utils"))]
mod test;

use std::sync::Arc;

use futures::{
    AsyncRead, AsyncWrite,
    future::{self, BoxFuture, Either},
};

#[cfg(any(test, feature = "test-utils"))]
pub use test::{
    RecordedMtData, RecordingDuplex, ReplayDuplex, recording_mt_context,
    recording_mt_context_with_limit, recording_mt_context_with_spawn_and_limit,
    recording_st_context, recording_st_context_with_limit, replay_mt_context,
    replay_mt_context_with_limit, replay_mt_context_with_spawn_and_limit, replay_st_context,
    test_mt_context, test_mt_context_with_spawn, test_st_context,
};

use crate::{ContextId, io::Io, mux::Mux, thread_pool::ThreadPool};

/// Default maximum number of [`map`](Context::map) items processed
/// concurrently, and with it the number of channels a `map` opens. Both parties
/// must agree on this value, so it is a fixed constant rather than data- or
/// timing-dependent.
pub const DEFAULT_CONCURRENCY_LIMIT: usize = 32;

/// A task execution context.
///
/// Each context owns an I/O channel and a [`ContextId`]. Use [`join`],
/// [`try_join`], [`map`] etc. to run sub-tasks concurrently; whether they
/// actually execute in parallel depends on how the context was built.
///
/// [`join`]: Self::join
/// [`try_join`]: Self::try_join
/// [`map`]: Self::map
pub struct Context {
    id: ContextId,
    io: Io,
    mode: Mode,
    /// Sub-namespace counter incremented on each fork.
    fork_counter: u32,
}

enum Mode {
    Single,
    Multi {
        mux: Arc<dyn Mux + Send + Sync>,
        /// Pool for parallel execution; `None` runs sub-tasks cooperatively
        /// on the caller's future.
        pool: Option<ThreadPool>,
        /// Maximum number of [`map`](Context::map) items processed
        /// concurrently.
        concurrency_limit: usize,
    },
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("id", &self.id)
            .field("io", &self.io)
            .finish_non_exhaustive()
    }
}

impl Context {
    /// Creates a new context backed by a single I/O channel.
    ///
    /// Sub-tasks spawned via [`join`], [`try_join`], [`map`] etc. share the
    /// channel and run **sequentially** in the order given. For parallel
    /// execution, build a [`Session`](crate::Session) and use
    /// [`Session::new_context`](crate::Session::new_context) instead.
    ///
    /// [`join`]: Self::join
    /// [`try_join`]: Self::try_join
    /// [`map`]: Self::map
    pub fn new_single_threaded<I>(io: I) -> Self
    where
        I: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        Self::from_io(Io::from_io(io))
    }

    pub(crate) fn from_io(io: Io) -> Self {
        Self {
            id: ContextId::default(),
            io,
            mode: Mode::Single,
            fork_counter: 0,
        }
    }

    pub(crate) fn for_session(
        id: ContextId,
        io: Io,
        mux: Arc<dyn Mux + Send + Sync>,
        pool: Option<ThreadPool>,
        concurrency_limit: usize,
    ) -> Self {
        Self {
            id,
            io,
            mode: Mode::Multi {
                mux,
                pool,
                concurrency_limit,
            },
            fork_counter: 0,
        }
    }

    fn child(&self, id: ContextId) -> Result<Self, ContextError> {
        let Mode::Multi {
            mux,
            pool,
            concurrency_limit,
        } = &self.mode
        else {
            unreachable!("child() called on a single-channel context");
        };
        let io = mux.open(id.as_ref()).map_err(ContextError::mux)?;
        Ok(Self {
            id,
            io,
            mode: Mode::Multi {
                mux: mux.clone(),
                pool: pool.clone(),
                concurrency_limit: *concurrency_limit,
            },
            fork_counter: 0,
        })
    }

    fn next_fork(&mut self) -> ContextId {
        let base = self.id.child(self.fork_counter);
        self.fork_counter += 1;
        base
    }

    /// Returns the context ID.
    pub fn id(&self) -> &ContextId {
        &self.id
    }

    /// Returns a reference to the I/O channel.
    pub fn io(&self) -> &Io {
        &self.io
    }

    /// Returns a mutable reference to the I/O channel.
    pub fn io_mut(&mut self) -> &mut Io {
        &mut self.io
    }

    /// Applies `f` to each item concurrently, returning the results in input
    /// order.
    ///
    /// # Channel usage
    ///
    /// Items are distributed round-robin over at most
    /// `concurrency_limit` *lanes*, each of which owns a single child context
    /// and processes its items sequentially. The number of channels ever opened
    /// is `min(items.len(), concurrency_limit)`, independent of the workload
    /// size, and that is also the concurrency bound.
    ///
    /// The lane assignment (`index % lanes`) and the order of items within a
    /// lane depend only on the item index, so both parties derive an identical
    /// channel layout and an identical per-channel message order. Both must
    /// configure the same limit — see
    /// [`SessionBuilder::concurrency_limit`](crate::SessionBuilder::concurrency_limit).
    ///
    /// # Requirements on `f`
    ///
    /// Items may share a channel, so each invocation must consume exactly
    /// the messages its counterpart produced — on every path, including
    /// early returns. Items sharing a channel are not isolated from each
    /// other: messages one item leaves unread are read by the next item on
    /// that channel, and since they carry the same wire types this is not
    /// detected.
    ///
    /// # Failure
    ///
    /// Not a recovery boundary. If any item fails, the results of this call
    /// and of every subsequent operation on this session are meaningless.
    pub async fn map<F, T, R>(&mut self, items: Vec<T>, f: F) -> Result<Vec<R>, ContextError>
    where
        F: for<'a> Fn(&'a mut Context, T) -> BoxFuture<'a, R> + Clone + Send + 'static,
        T: Send + 'static,
        R: Send + 'static,
    {
        let (pool, concurrency_limit) = match &self.mode {
            Mode::Single => {
                let mut results = Vec::with_capacity(items.len());
                for item in items {
                    results.push(f(self, item).await);
                }
                return Ok(results);
            }
            Mode::Multi {
                pool,
                concurrency_limit,
                ..
            } => (pool.clone(), *concurrency_limit),
        };

        let len = items.len();
        if len == 0 {
            // Still consume a fork index so that both parties stay in sync.
            let _ = self.next_fork();
            return Ok(Vec::new());
        }

        let parent_id = self.next_fork();

        let lanes = len.min(concurrency_limit);
        let mut queues: Vec<Vec<T>> = (0..lanes)
            .map(|_| Vec::with_capacity(len.div_ceil(lanes)))
            .collect();
        for (i, item) in items.into_iter().enumerate() {
            queues[i % lanes].push(item);
        }

        // Open every lane's channel before spawning any task. `child` only
        // opens the channel and never touches the wire, so this makes
        // channel-open failure atomic: either every lane starts, or none do.
        // Interleaving open and spawn instead would let a later lane's
        // open failure drop `tasks`, cancelling already-running earlier
        // lanes mid-message and desyncing the peer.
        let mut ctxs = Vec::with_capacity(lanes);
        for lane in 0..lanes {
            let lane = u32::try_from(lane).expect("lane count fits in u32");
            ctxs.push(self.child(parent_id.child(lane))?);
        }

        let mut tasks = Vec::with_capacity(lanes);
        for (mut ctx, queue) in ctxs.into_iter().zip(queues) {
            let f = f.clone();
            tasks.push(run(pool.as_ref(), async move {
                let mut results = Vec::with_capacity(queue.len());
                for item in queue {
                    results.push(f(&mut ctx, item).await);
                }
                results
            }));
        }

        // Interleave lane outputs back into input order: lane `l`'s j-th
        // result corresponds to original index `l + j * lanes`, the mirror
        // of how items were scattered into lanes above.
        let mut iters: Vec<_> = future::join_all(tasks)
            .await
            .into_iter()
            .map(Vec::into_iter)
            .collect();
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            out.push(iters[i % lanes].next().expect("one result per item"));
        }
        Ok(out)
    }

    /// Runs `a` and `b` concurrently and returns both results.
    pub async fn join<A, B, RA, RB>(&mut self, a: A, b: B) -> Result<(RA, RB), ContextError>
    where
        A: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, RA> + Send + 'static,
        B: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, RB> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
    {
        if matches!(self.mode, Mode::Single) {
            let ra = a(self).await;
            let rb = b(self).await;
            return Ok((ra, rb));
        }

        let parent_id = self.next_fork();
        let pool = self.pool().cloned();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;

        let task_a = run(pool.as_ref(), async move { a(&mut ctx_a).await });
        let task_b = run(pool.as_ref(), async move { b(&mut ctx_b).await });
        Ok(future::join(task_a, task_b).await)
    }

    /// Like [`Context::join`], but short-circuits as soon as either branch
    /// returns an error, potentially cancelling the other.
    pub async fn try_join<A, B, RA, RB, E>(
        &mut self,
        a: A,
        b: B,
    ) -> Result<Result<(RA, RB), E>, ContextError>
    where
        A: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RA, E>> + Send + 'static,
        B: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RB, E>> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
        E: Send + 'static,
    {
        if matches!(self.mode, Mode::Single) {
            return Ok(async {
                let ra = a(self).await?;
                let rb = b(self).await?;
                Ok((ra, rb))
            }
            .await);
        }

        let parent_id = self.next_fork();
        let pool = self.pool().cloned();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;

        let task_a = run(pool.as_ref(), async move { a(&mut ctx_a).await });
        let task_b = run(pool.as_ref(), async move { b(&mut ctx_b).await });
        Ok(future::try_join(task_a, task_b).await)
    }

    /// Same as [`Context::try_join`], but with three branches.
    pub async fn try_join3<A, B, C, RA, RB, RC, E>(
        &mut self,
        a: A,
        b: B,
        c: C,
    ) -> Result<Result<(RA, RB, RC), E>, ContextError>
    where
        A: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RA, E>> + Send + 'static,
        B: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RB, E>> + Send + 'static,
        C: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RC, E>> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
        RC: Send + 'static,
        E: Send + 'static,
    {
        if matches!(self.mode, Mode::Single) {
            return Ok(async {
                let ra = a(self).await?;
                let rb = b(self).await?;
                let rc = c(self).await?;
                Ok((ra, rb, rc))
            }
            .await);
        }

        let parent_id = self.next_fork();
        let pool = self.pool().cloned();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;
        let mut ctx_c = self.child(parent_id.child(2))?;

        let task_a = run(pool.as_ref(), async move { a(&mut ctx_a).await });
        let task_b = run(pool.as_ref(), async move { b(&mut ctx_b).await });
        let task_c = run(pool.as_ref(), async move { c(&mut ctx_c).await });
        Ok(future::try_join3(task_a, task_b, task_c).await)
    }

    /// Same as [`Context::try_join`], but with four branches.
    pub async fn try_join4<A, B, C, D, RA, RB, RC, RD, E>(
        &mut self,
        a: A,
        b: B,
        c: C,
        d: D,
    ) -> Result<Result<(RA, RB, RC, RD), E>, ContextError>
    where
        A: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RA, E>> + Send + 'static,
        B: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RB, E>> + Send + 'static,
        C: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RC, E>> + Send + 'static,
        D: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RD, E>> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
        RC: Send + 'static,
        RD: Send + 'static,
        E: Send + 'static,
    {
        if matches!(self.mode, Mode::Single) {
            return Ok(async {
                let ra = a(self).await?;
                let rb = b(self).await?;
                let rc = c(self).await?;
                let rd = d(self).await?;
                Ok((ra, rb, rc, rd))
            }
            .await);
        }

        let parent_id = self.next_fork();
        let pool = self.pool().cloned();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;
        let mut ctx_c = self.child(parent_id.child(2))?;
        let mut ctx_d = self.child(parent_id.child(3))?;

        let task_a = run(pool.as_ref(), async move { a(&mut ctx_a).await });
        let task_b = run(pool.as_ref(), async move { b(&mut ctx_b).await });
        let task_c = run(pool.as_ref(), async move { c(&mut ctx_c).await });
        let task_d = run(pool.as_ref(), async move { d(&mut ctx_d).await });
        Ok(future::try_join4(task_a, task_b, task_c, task_d).await)
    }

    fn pool(&self) -> Option<&ThreadPool> {
        if let Mode::Multi { pool, .. } = &self.mode {
            pool.as_ref()
        } else {
            None
        }
    }
}

/// Spawns `fut` on `pool` if one is provided, otherwise yields the future
/// as-is. The output type is identical either way.
fn run<F>(pool: Option<&ThreadPool>, fut: F) -> impl std::future::Future<Output = F::Output> + Send
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    match pool {
        Some(pool) => Either::Left(crate::thread_pool::spawn_on(pool, fut)),
        None => Either::Right(fut),
    }
}

/// Error for [`Context`].
#[derive(Debug, thiserror::Error)]
#[error("context mux error: {source}")]
pub struct ContextError {
    #[source]
    source: std::io::Error,
}

impl ContextError {
    fn mux(source: std::io::Error) -> Self {
        Self { source }
    }
}
