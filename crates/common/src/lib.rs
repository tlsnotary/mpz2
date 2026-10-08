//! Common functionality for `mpz`.
//!
//! This crate provides various common functionalities needed for modeling
//! protocol execution, I/O, and multi-threading.
//!
//! This crate does not provide any cryptographic primitives, see `mpz-core` for
//! that.

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

pub mod context;
#[cfg(any(test, feature = "future"))]
pub mod future;
mod id;
#[cfg(any(test, feature = "ideal"))]
pub mod ideal;
pub mod io;
pub mod mux;
pub mod session;
#[cfg(feature = "sync")]
pub mod sync;
mod task;
pub mod thread_pool;

pub use context::{Context, ContextError};
pub use id::ContextId;
pub use session::{Session, SessionBuilder};
pub use task::Task;
pub use thread_pool::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};

use async_trait::async_trait;

/// A functionality that can be flushed.
#[async_trait]
pub trait Flush {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns `true` if the functionality wants to be flushed.
    fn wants_flush(&self) -> bool;

    /// Flushes the functionality.
    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error>;
}
