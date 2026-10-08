//! Recording infrastructure for protocol message capture.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

use crate::{
    context::Context,
    io::Io,
    mux::Mux,
    session::{Session, SessionBuilder},
    thread_pool::ThreadPool,
};

/// A duplex stream that records all bytes written.
///
/// Used for recording protocol messages for replay in isolated benchmarks.
pub struct RecordingDuplex {
    inner: Compat<tokio::io::DuplexStream>,
    recorded: Arc<Mutex<Vec<u8>>>,
}

impl RecordingDuplex {
    /// Creates a new recording duplex wrapping the given stream.
    pub fn new(inner: tokio::io::DuplexStream, recorded: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            inner: inner.compat(),
            recorded,
        }
    }
}

impl AsyncRead for RecordingDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RecordingDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.recorded.lock().unwrap().extend_from_slice(&buf[..*n]);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Creates a pair of single-threaded contexts where writes from ctx_1 to ctx_0
/// are recorded.
///
/// Returns `(ctx_0, ctx_1, recorded)` where `recorded` contains all bytes
/// written by ctx_1. This is useful for recording protocol messages for replay
/// in isolated benchmarks.
///
/// Note: Unlike `test_st_context`, this uses framed byte transport instead of
/// memory channels, which may have slightly different performance
/// characteristics.
pub fn recording_st_context(io_buffer: usize) -> (Context, Context, Arc<Mutex<Vec<u8>>>) {
    let (io_0, io_1) = tokio::io::duplex(io_buffer);

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let recording_io_1 = RecordingDuplex::new(io_1, recorded.clone());

    (
        Context::new_single_threaded(io_0.compat()),
        Context::new_single_threaded(recording_io_1),
        recorded,
    )
}

/// Creates a pair of single-threaded contexts with a custom frame limit where
/// writes from ctx_1 to ctx_0 are recorded.
///
/// Like [`recording_st_context`], but allows setting a custom maximum frame
/// size. Use this when protocol messages exceed the default 8MB frame limit.
///
/// # Arguments
///
/// * `io_buffer` - Size of the I/O buffer.
/// * `max_frame_length` - Maximum frame size in bytes.
pub fn recording_st_context_with_limit(
    io_buffer: usize,
    max_frame_length: usize,
) -> (Context, Context, Arc<Mutex<Vec<u8>>>) {
    let (io_0, io_1) = tokio::io::duplex(io_buffer);

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let recording_io_1 = RecordingDuplex::new(io_1, recorded.clone());

    (
        Context::from_io(Io::from_io_with_limit(io_0.compat(), max_frame_length)),
        Context::from_io(Io::from_io_with_limit(recording_io_1, max_frame_length)),
        recorded,
    )
}

// ============================================================================
// Multi-threaded recording infrastructure
// ============================================================================

/// Recorded data for multi-threaded context replay.
///
/// Stores bytes recorded from each channel, keyed by context ID.
#[derive(Debug, Clone, Default)]
pub struct RecordedMtData {
    /// Recorded bytes per channel.
    pub channels: HashMap<Vec<u8>, Vec<u8>>,
}

/// Shared state for recording test mux.
///
/// Uses byte-based tokio duplex channels (like ST recording) instead of
/// type-erased MemoryDuplex, allowing byte-level recording.
#[derive(Default)]
struct RecordingMuxState {
    /// Channels waiting to be opened by role A.
    waiting_a: HashMap<Vec<u8>, Compat<tokio::io::DuplexStream>>,
    /// Channels waiting to be opened by role B.
    waiting_b: HashMap<Vec<u8>, RecordingDuplexMt>,
    /// Track which channels have been opened.
    opened: std::collections::HashSet<Vec<u8>>,
}

/// Role in the recording mux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordingRole {
    /// Role A: receives from role B (no recording on this side).
    A,
    /// Role B: sends to role A (recording enabled).
    B,
}

/// A test mux that records writes from role B using byte-level recording.
///
/// Similar to `TestFramedMux` but uses tokio duplex (byte streams) instead of
/// MemoryDuplex (type-erased channels), allowing us to record raw bytes.
#[derive(Clone)]
struct RecordingTestMux {
    role: RecordingRole,
    buffer: usize,
    max_frame_length: Option<usize>,
    state: Arc<Mutex<RecordingMuxState>>,
    recorded: Arc<Mutex<RecordedMtData>>,
}

impl std::fmt::Debug for RecordingTestMux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingTestMux")
            .field("role", &self.role)
            .field("buffer", &self.buffer)
            .finish_non_exhaustive()
    }
}

impl Mux for RecordingTestMux {
    fn open(&self, id: &[u8]) -> Result<Io, std::io::Error> {
        let mut state = self.state.lock().unwrap();
        let id_vec = id.to_vec();

        // Check if channel already exists from the other side
        match self.role {
            RecordingRole::A => {
                if let Some(stream) = state.waiting_a.remove(&id_vec) {
                    return Ok(if let Some(limit) = self.max_frame_length {
                        Io::from_io_with_limit(stream, limit)
                    } else {
                        Io::from_io(stream)
                    });
                }
            }
            RecordingRole::B => {
                if let Some(recording_stream) = state.waiting_b.remove(&id_vec) {
                    return Ok(if let Some(limit) = self.max_frame_length {
                        Io::from_io_with_limit(recording_stream, limit)
                    } else {
                        Io::from_io(recording_stream)
                    });
                }
            }
        }

        // Check for duplicate
        if !state.opened.insert(id_vec.clone()) {
            return Err(std::io::Error::other("duplicate stream id"));
        }

        // Create new byte-based channel pair
        let (stream_a, stream_b) = tokio::io::duplex(self.buffer);

        // Role B's writes are recorded
        let recorded_for_channel = self.recorded.clone();
        let channel_id = id_vec.clone();

        match self.role {
            RecordingRole::A => {
                // A gets plain stream, B gets recording stream
                let recording_stream =
                    RecordingDuplexWithId::new(stream_b, channel_id, recorded_for_channel);
                state
                    .waiting_b
                    .insert(id_vec, recording_stream.into_recording_duplex());
                Ok(if let Some(limit) = self.max_frame_length {
                    Io::from_io_with_limit(stream_a.compat(), limit)
                } else {
                    Io::from_io(stream_a.compat())
                })
            }
            RecordingRole::B => {
                // B gets recording stream, A gets plain stream
                state.waiting_a.insert(id_vec, stream_a.compat());
                let recording_stream =
                    RecordingDuplexWithId::new(stream_b, channel_id, recorded_for_channel);
                Ok(if let Some(limit) = self.max_frame_length {
                    Io::from_io_with_limit(recording_stream.into_recording_duplex(), limit)
                } else {
                    Io::from_io(recording_stream.into_recording_duplex())
                })
            }
        }
    }
}

/// Helper to create RecordingDuplex with per-channel recording.
struct RecordingDuplexWithId {
    inner: tokio::io::DuplexStream,
    channel_id: Vec<u8>,
    recorded: Arc<Mutex<RecordedMtData>>,
}

impl RecordingDuplexWithId {
    fn new(
        inner: tokio::io::DuplexStream,
        channel_id: Vec<u8>,
        recorded: Arc<Mutex<RecordedMtData>>,
    ) -> Self {
        Self {
            inner,
            channel_id,
            recorded,
        }
    }

    fn into_recording_duplex(self) -> RecordingDuplexMt {
        RecordingDuplexMt {
            inner: self.inner.compat(),
            channel_id: self.channel_id,
            recorded: self.recorded,
        }
    }
}

/// A duplex stream that records all bytes written, tagged by channel ID.
///
/// Like `RecordingDuplex` but stores bytes per-channel for MT contexts.
struct RecordingDuplexMt {
    inner: Compat<tokio::io::DuplexStream>,
    channel_id: Vec<u8>,
    recorded: Arc<Mutex<RecordedMtData>>,
}

impl AsyncRead for RecordingDuplexMt {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RecordingDuplexMt {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            let mut data = self.recorded.lock().unwrap();
            data.channels
                .entry(self.channel_id.clone())
                .or_default()
                .extend_from_slice(&buf[..*n]);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Creates a pair of recording test mux instances.
///
/// Writes from mux_1 (role B) are recorded in the returned `RecordedMtData`.
fn recording_test_mux(
    buffer: usize,
    max_frame_length: Option<usize>,
) -> (
    RecordingTestMux,
    RecordingTestMux,
    Arc<Mutex<RecordedMtData>>,
) {
    let state = Arc::new(Mutex::new(RecordingMuxState::default()));
    let recorded = Arc::new(Mutex::new(RecordedMtData::default()));

    (
        RecordingTestMux {
            role: RecordingRole::A,
            buffer,
            max_frame_length,
            state: state.clone(),
            recorded: recorded.clone(),
        },
        RecordingTestMux {
            role: RecordingRole::B,
            buffer,
            max_frame_length,
            state,
            recorded: recorded.clone(),
        },
        recorded,
    )
}

/// Creates a pair of multi-threaded contexts where writes from ctx_1 are
/// recorded.
///
/// Returns `(ctx_0, ctx_1, recorded)` where `recorded` contains all bytes
/// written by ctx_1 on each channel.
///
/// # Arguments
///
/// * `io_buffer` - Size of the I/O buffer per channel.
pub fn recording_mt_context(io_buffer: usize) -> (Session, Session, Arc<Mutex<RecordedMtData>>) {
    let (mux_0, mux_1, recorded) = recording_test_mux(io_buffer, None);

    (
        SessionBuilder::default().build(mux_0).unwrap(),
        SessionBuilder::default().build(mux_1).unwrap(),
        recorded,
    )
}

/// Creates a pair of multi-threaded contexts where writes from ctx_1 are
/// recorded, with a custom frame length limit.
///
/// # Arguments
///
/// * `io_buffer` - Size of the I/O buffer per channel.
/// * `max_frame_length` - Maximum frame size in bytes.
pub fn recording_mt_context_with_limit(
    io_buffer: usize,
    max_frame_length: usize,
) -> (Session, Session, Arc<Mutex<RecordedMtData>>) {
    let (mux_0, mux_1, recorded) = recording_test_mux(io_buffer, Some(max_frame_length));

    (
        SessionBuilder::default().build(mux_0).unwrap(),
        SessionBuilder::default().build(mux_1).unwrap(),
        recorded,
    )
}

/// Like [`recording_mt_context_with_limit`], but uses a custom worker spawn
/// callback (e.g. `web_spawn::spawn` on wasm) and a fixed concurrency level.
///
/// The same `spawn` callback is used for both sessions.
pub fn recording_mt_context_with_spawn_and_limit<F>(
    io_buffer: usize,
    max_frame_length: usize,
    concurrency: usize,
    spawn: F,
) -> (Session, Session, Arc<Mutex<RecordedMtData>>)
where
    F: Fn(Box<dyn FnOnce() + Send + 'static>) -> Result<(), std::io::Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    let (mux_0, mux_1, recorded) = recording_test_mux(io_buffer, Some(max_frame_length));
    let pool_0 = ThreadPool::builder()
        .num_threads(concurrency)
        .spawn(spawn.clone())
        .build()
        .unwrap();
    let pool_1 = ThreadPool::builder()
        .num_threads(concurrency)
        .spawn(spawn)
        .build()
        .unwrap();
    let exec_0 = SessionBuilder::default().pool(pool_0).build(mux_0).unwrap();
    let exec_1 = SessionBuilder::default().pool(pool_1).build(mux_1).unwrap();
    (exec_0, exec_1, recorded)
}
