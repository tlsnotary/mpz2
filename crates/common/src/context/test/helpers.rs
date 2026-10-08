//! Basic test context helpers.

use serio::channel::duplex;

use crate::{
    context::Context,
    io::Io,
    mux::test_framed_mux,
    session::{Session, SessionBuilder},
    thread_pool::ThreadPool,
};

/// Creates a pair of single-threaded contexts using memory I/O channels.
pub fn test_st_context(io_buffer: usize) -> (Context, Context) {
    let (io_0, io_1) = duplex(io_buffer);

    (
        Context::from_io(Io::from_channel(io_0)),
        Context::from_io(Io::from_channel(io_1)),
    )
}

/// Creates a pair of multi-threaded sessions sharing multiplexed I/O channels.
pub fn test_mt_context(io_buffer: usize) -> (Session, Session) {
    let (mux_0, mux_1) = test_framed_mux(io_buffer);

    (
        SessionBuilder::default().build(mux_0).unwrap(),
        SessionBuilder::default().build(mux_1).unwrap(),
    )
}

/// Like [`test_mt_context`], but uses a custom worker spawn callback (e.g.
/// `web_spawn::spawn` on wasm).
pub fn test_mt_context_with_spawn<F>(io_buffer: usize, spawn: F) -> (Session, Session)
where
    F: Fn(Box<dyn FnOnce() + Send + 'static>) -> Result<(), std::io::Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    let (mux_0, mux_1) = test_framed_mux(io_buffer);
    let pool_0 = ThreadPool::builder().spawn(spawn.clone()).build().unwrap();
    let pool_1 = ThreadPool::builder().spawn(spawn).build().unwrap();

    (
        SessionBuilder::default().pool(pool_0).build(mux_0).unwrap(),
        SessionBuilder::default().pool(pool_1).build(mux_1).unwrap(),
    )
}
