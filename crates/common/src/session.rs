//! Async session.
//!
//! A [`Session`] hands out [`Context`]s, each with a distinct [`ContextId`]
//! and its own I/O channel from the configured multiplexer. Sub-tasks
//! spawned through a `Context` run on the session's [`ThreadPool`] — the
//! global pool by default, a builder-supplied pool, or, when
//! [`SessionBuilder::cooperative`] is set, the caller's future.

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use crate::{
    Context, ContextId,
    context::DEFAULT_CONCURRENCY_LIMIT,
    mux::Mux,
    thread_pool::{ThreadPool, ThreadPoolBuildError},
};

/// An async session.
pub struct Session {
    /// Pool sub-tasks run on; `None` runs them cooperatively on the caller.
    pool: Option<ThreadPool>,
    mux: Arc<dyn Mux + Send + Sync>,
    prefix: ContextId,
    next_context: AtomicU32,
    /// Maximum number of [`Context::map`] items processed concurrently.
    concurrency_limit: usize,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("pool", &self.pool)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
enum PoolMode {
    /// Use a specific pool.
    Pool(ThreadPool),
    /// Use the global pool (resolved at `build` time).
    #[default]
    Global,
    /// Run sub-tasks cooperatively on the caller's future.
    Cooperative,
}

impl std::fmt::Debug for PoolMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pool(pool) => f.debug_tuple("Pool").field(pool).finish(),
            Self::Global => f.write_str("Global"),
            Self::Cooperative => f.write_str("Cooperative"),
        }
    }
}

/// Builder for [`Session`].
#[derive(Debug)]
pub struct SessionBuilder {
    pool: PoolMode,
    prefix: ContextId,
    concurrency_limit: usize,
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self {
            pool: PoolMode::default(),
            prefix: ContextId::default(),
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
        }
    }
}

impl SessionBuilder {
    /// Sets the pool the session will run tasks on.
    ///
    /// Overrides the default of using the global pool
    /// ([`ThreadPool::global`]).
    pub fn pool(mut self, pool: ThreadPool) -> Self {
        self.pool = PoolMode::Pool(pool);
        self
    }

    /// Configures the session to run sub-tasks cooperatively on the caller's
    /// future rather than on a thread pool.
    ///
    /// Each sub-task is still given its own I/O channel from the mux, but
    /// they are polled by the caller — no threads are spawned.
    pub fn cooperative(mut self) -> Self {
        self.pool = PoolMode::Cooperative;
        self
    }

    /// Sets a namespace prefix applied to all contexts created by the
    /// session.
    ///
    /// Useful when several sub-protocols share a mux and need to be kept in
    /// disjoint ID spaces.
    pub fn prefix(mut self, prefix: impl AsRef<[u8]>) -> Self {
        self.prefix = ContextId::from_prefix(prefix);
        self
    }

    /// Sets the maximum number of [`Context::map`] items processed
    /// concurrently, bounding how many sub-channels are open at once.
    ///
    /// Both parties **must** configure the same limit so they open the same
    /// sliding window of channels and stay in lockstep. The limit is clamped
    /// to a minimum of `1`. Defaults to [`DEFAULT_CONCURRENCY_LIMIT`].
    pub fn concurrency_limit(mut self, limit: usize) -> Self {
        self.concurrency_limit = limit.max(1);
        self
    }

    /// Builds the session with the given multiplexer.
    ///
    /// Returns an error if the builder is configured to use the global pool
    /// (the default) but the global pool cannot be built — for instance on
    /// platforms without OS threads. Callers that want to run without a
    /// thread pool in those cases should opt in via
    /// [`cooperative`](Self::cooperative).
    pub fn build<M: Mux + Send + Sync + 'static>(
        self,
        mux: M,
    ) -> Result<Session, ThreadPoolBuildError> {
        let pool = match self.pool {
            PoolMode::Pool(pool) => Some(pool),
            PoolMode::Global => Some(ThreadPool::try_global()?),
            PoolMode::Cooperative => None,
        };
        Ok(Session {
            pool,
            mux: Arc::new(mux),
            prefix: self.prefix,
            next_context: AtomicU32::new(0),
            concurrency_limit: self.concurrency_limit,
        })
    }
}

impl Session {
    /// Creates a new builder.
    pub fn builder() -> SessionBuilder {
        SessionBuilder::default()
    }

    /// Returns the pool this session runs tasks on, or `None` if it runs
    /// sub-tasks cooperatively.
    pub fn pool(&self) -> Option<&ThreadPool> {
        self.pool.as_ref()
    }

    /// Creates a new context.
    ///
    /// Each context produced by a session is given a distinct ID under the
    /// session's configured prefix.
    pub fn new_context(&self) -> Result<Context, std::io::Error> {
        let index = self.next_context.fetch_add(1, Ordering::Relaxed);
        let id = self.prefix.child(index);
        let io = self.mux.open(id.as_ref())?;
        Ok(Context::for_session(
            id,
            io,
            self.mux.clone(),
            self.pool.clone(),
            self.concurrency_limit,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mux::test_framed_mux;
    use serio::{SinkExt, StreamExt};

    fn test_pool() -> ThreadPool {
        ThreadPool::builder().num_threads(2).build().unwrap()
    }

    #[test]
    fn test_session_spawn() {
        let (mux_a, _mux_b) = test_framed_mux(1024);
        let session = Session::builder().pool(test_pool()).build(mux_a).unwrap();

        let mut ctx = session.new_context().unwrap();
        let (a, b) = futures::executor::block_on(ctx.join(
            |_ctx| Box::pin(async move { 21 }),
            |_ctx| Box::pin(async move { 21 }),
        ))
        .unwrap();

        assert_eq!(a + b, 42);
    }

    #[test]
    fn test_session_map() {
        let (mux_a, _mux_b) = test_framed_mux(1024);
        let session = Session::builder().pool(test_pool()).build(mux_a).unwrap();

        let mut ctx = session.new_context().unwrap();

        let items = vec![1, 2, 3, 4, 5];
        let results =
            futures::executor::block_on(ctx.map(items, |_ctx, x| Box::pin(async move { x * 2 })));

        assert_eq!(results.unwrap(), vec![2, 4, 6, 8, 10]);
    }

    #[test]
    fn test_session_join() {
        let (mux_a, _mux_b) = test_framed_mux(1024);
        let session = Session::builder().pool(test_pool()).build(mux_a).unwrap();

        let mut ctx = session.new_context().unwrap();

        let result = futures::executor::block_on(ctx.join(
            |_ctx| Box::pin(async move { 1 + 1 }),
            |_ctx| Box::pin(async move { 2 + 2 }),
        ));

        assert_eq!(result.unwrap(), (2, 4));
    }

    #[test]
    fn test_session_io() {
        let (mux_a, mux_b) = test_framed_mux(1024);

        let session_a = Session::builder().pool(test_pool()).build(mux_a).unwrap();
        let session_b = Session::builder().pool(test_pool()).build(mux_b).unwrap();

        let mut ctx_a = session_a.new_context().unwrap();
        let mut ctx_b = session_b.new_context().unwrap();

        let (_, (val1, val2)) = futures::executor::block_on(futures::future::join(
            async {
                ctx_a.io_mut().send(42u32).await.unwrap();
                ctx_a.io_mut().send(123u32).await.unwrap();
            },
            async {
                let val1: u32 = ctx_b.io_mut().next().await.unwrap().unwrap();
                let val2: u32 = ctx_b.io_mut().next().await.unwrap().unwrap();
                (val1, val2)
            },
        ));

        assert_eq!(val1, 42);
        assert_eq!(val2, 123);
    }

    #[test]
    fn test_session_map_with_io() {
        let (mux_a, mux_b) = test_framed_mux(1024);

        let pool = ThreadPool::builder().num_threads(4).build().unwrap();
        let session_a = Session::builder().pool(pool.clone()).build(mux_a).unwrap();
        let session_b = Session::builder().pool(pool).build(mux_b).unwrap();

        let mut ctx_a = session_a.new_context().unwrap();
        let mut ctx_b = session_b.new_context().unwrap();

        let items_a = vec![1u32, 2, 3, 4];
        let items_b = vec![10u32, 20, 30, 40];

        let task_a = ctx_a.map(items_a, |ctx, x| {
            Box::pin(async move {
                ctx.io_mut().send(x).await.unwrap();
            })
        });

        let task_b = ctx_b.map(items_b, |ctx, x| {
            Box::pin(async move {
                let received: u32 = ctx.io_mut().next().await.unwrap().unwrap();
                received + x
            })
        });

        let (results_a, results_b) =
            futures::executor::block_on(futures::future::join(task_a, task_b));

        assert!(results_a.is_ok());
        let results_b = results_b.unwrap();

        assert_eq!(results_b, vec![11, 22, 33, 44]);
    }

    #[test]
    fn test_global_pool_shared() {
        let (mux_a, mux_b) = test_framed_mux(1024);
        let session_a = Session::builder().prefix(b"a").build(mux_a).unwrap();
        let session_b = Session::builder().prefix(b"b").build(mux_b).unwrap();

        assert!(!session_a.pool().unwrap().is_shutdown());
        assert!(!session_b.pool().unwrap().is_shutdown());

        let mut ctx_a = session_a.new_context().unwrap();
        let mut ctx_b = session_b.new_context().unwrap();

        let (sum_a, sum_b) = futures::executor::block_on(futures::future::join(
            async {
                let (x, y) = ctx_a
                    .join(
                        |_ctx| Box::pin(async move { 10 }),
                        |_ctx| Box::pin(async move { 20 }),
                    )
                    .await
                    .unwrap();
                x + y
            },
            async {
                let (x, y) = ctx_b
                    .join(
                        |_ctx| Box::pin(async move { 1 }),
                        |_ctx| Box::pin(async move { 2 }),
                    )
                    .await
                    .unwrap();
                x + y
            },
        ));

        assert_eq!(sum_a, 30);
        assert_eq!(sum_b, 3);

        drop(session_a);
        assert!(!session_b.pool().unwrap().is_shutdown());
    }

    #[test]
    fn test_cooperative_session() {
        let (mux_a, _mux_b) = test_framed_mux(1024);
        let session = Session::builder().cooperative().build(mux_a).unwrap();

        assert!(session.pool().is_none());

        let mut ctx = session.new_context().unwrap();
        let (a, b) = futures::executor::block_on(ctx.join(
            |_ctx| Box::pin(async move { 21 }),
            |_ctx| Box::pin(async move { 21 }),
        ))
        .unwrap();

        assert_eq!(a + b, 42);
    }
}
