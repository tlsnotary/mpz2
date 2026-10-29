//! Shared, target-agnostic body for the isolated Ferret sender benchmarks.
//!
//! Included via `#[path]` by `crates/ot/benches/ferret/sender.rs` (and later by
//! the browser harness). ST/MT suffixed.

use mpz_common::{
    Context, Flush, Session,
    context::{
        RecordedMtData, recording_mt_context_with_limit, recording_st_context_with_limit,
        replay_mt_context_with_limit, replay_st_context,
    },
};
use mpz_core::Block;
use mpz_ot::{
    ferret::{FerretConfig, Receiver, Sender},
    ideal::rcot::{IdealRCOTSender, ideal_rcot},
};
use mpz_ot_core::rcot::{RCOTReceiver, RCOTSender};
use rand::{RngExt, SeedableRng, rngs::StdRng};

/// Number of OTs generated per benchmark iteration.
pub const OT_COUNT: usize = 10_000_000;

/// Ferret messages include SPCOT data which can be large; use a large buffer
/// for production parameters.
pub fn max_frame_length() -> usize {
    64 * 1024 * 1024 // 64 MB
}

/// Creates the Ferret config for benchmarking.
pub fn bench_config() -> FerretConfig {
    FerretConfig::default()
}

/// Recorded data needed for deterministic ST replay.
pub struct RecordedSender {
    /// Recorded bytes from receiver -> sender.
    pub bytes: Vec<u8>,
    /// Delta correlation.
    pub delta: Block,
    /// Seed for `IdealRCOTSender`.
    pub cot_seed: Block,
    /// Seed for the Ferret sender.
    pub sender_seed: Block,
    /// Correlations actually produced (OT_COUNT rounded up to whole
    /// iterations).
    // Only the native bench entry points read this; the browser harness reuses
    // the body without reporting throughput.
    #[allow(dead_code)]
    pub actual_count: usize,
}

/// Recorded data needed for deterministic MT replay.
pub struct RecordedSenderMt {
    /// Recorded bytes from receiver -> sender (per channel).
    pub data: RecordedMtData,
    /// Delta correlation.
    pub delta: Block,
    /// Seed for `IdealRCOTSender`.
    pub cot_seed: Block,
    /// Seed for the Ferret sender.
    pub sender_seed: Block,
    /// Correlations actually produced (OT_COUNT rounded up to whole
    /// iterations).
    // Only the native bench entry points read this; the browser harness reuses
    // the body without reporting throughput.
    #[allow(dead_code)]
    pub actual_count: usize,
}

// ============================================================================
// Single-threaded (ST)
// ============================================================================

/// Runs the full Ferret protocol with ST contexts, recording receiver->sender.
#[allow(clippy::too_many_arguments)]
pub async fn run_protocol_record_receiver_st(
    ctx_sender: &mut Context,
    ctx_receiver: &mut Context,
    config: FerretConfig,
    delta: Block,
    cot_seed: Block,
    sender_seed: Block,
    receiver_seed: Block,
    ot_count: usize,
) -> usize {
    let (cot_send, cot_recv) = ideal_rcot(cot_seed, delta);

    let mut sender = Sender::new(config.clone(), sender_seed, cot_send);
    let mut receiver = Receiver::new(config, receiver_seed, cot_recv);

    futures::join!(
        async {
            sender.alloc(ot_count).unwrap();
            let output = sender.queue_send_rcot(ot_count).unwrap();
            sender.flush(ctx_sender).await.unwrap();
            let _ = output.await.unwrap();
        },
        async {
            receiver.alloc(ot_count).unwrap();
            let output = receiver.queue_recv_rcot(ot_count).unwrap();
            receiver.flush(ctx_receiver).await.unwrap();
            let _ = output.await.unwrap();
        }
    );

    // Ferret extends in whole LPN iterations, so it produces more than the
    // requested OT_COUNT. The surplus stays buffered after the request is
    // fulfilled, so the realized count is OT_COUNT plus what remains available.
    ot_count + sender.available()
}

/// Records receiver->sender messages for ST sender replay.
pub async fn record_for_sender_st(seed: u64, ot_count: usize) -> RecordedSender {
    let mut rng = StdRng::seed_from_u64(seed);
    let delta: Block = rng.random();
    let cot_seed: Block = rng.random();
    let sender_seed: Block = rng.random();
    let receiver_seed: Block = rng.random();

    // ctx_1 (receiver) is recorded, ctx_0 (sender) receives
    let (mut ctx_sender, mut ctx_receiver, recorded) =
        recording_st_context_with_limit(1024 * 1024, max_frame_length());

    let actual_count = run_protocol_record_receiver_st(
        &mut ctx_sender,
        &mut ctx_receiver,
        bench_config(),
        delta,
        cot_seed,
        sender_seed,
        receiver_seed,
        ot_count,
    )
    .await;

    RecordedSender {
        bytes: recorded.lock().unwrap().clone(),
        delta,
        cot_seed,
        sender_seed,
        actual_count,
    }
}

/// Builds an ST replay context for the sender.
pub fn replay_sender_st(recorded: Vec<u8>) -> Context {
    replay_st_context(recorded, max_frame_length())
}

/// Runs ST sender only with replay context.
pub async fn run_sender_with_replay_st(ctx: &mut Context, data: &RecordedSender) {
    let cot_send = IdealRCOTSender::new(data.cot_seed, data.delta);
    let mut sender = Sender::new(bench_config(), data.sender_seed, cot_send);

    sender.alloc(OT_COUNT).unwrap();
    let output = sender.queue_send_rcot(OT_COUNT).unwrap();
    sender.flush(ctx).await.unwrap();
    let _ = output.await.unwrap();
}

// ============================================================================
// Multi-threaded (MT)
// ============================================================================

/// Runs the full Ferret protocol with MT contexts, recording receiver->sender.
#[allow(clippy::too_many_arguments)]
pub async fn run_protocol_record_receiver_mt(
    exec_sender: &mut Session,
    exec_receiver: &mut Session,
    config: FerretConfig,
    delta: Block,
    cot_seed: Block,
    sender_seed: Block,
    receiver_seed: Block,
    ot_count: usize,
) -> usize {
    let (cot_send, cot_recv) = ideal_rcot(cot_seed, delta);

    let mut sender = Sender::new(config.clone(), sender_seed, cot_send);
    let mut receiver = Receiver::new(config, receiver_seed, cot_recv);

    let mut ctx_sender = exec_sender.new_context().unwrap();
    let mut ctx_receiver = exec_receiver.new_context().unwrap();

    futures::join!(
        async {
            sender.alloc(ot_count).unwrap();
            let output = sender.queue_send_rcot(ot_count).unwrap();
            sender.flush(&mut ctx_sender).await.unwrap();
            let _ = output.await.unwrap();
        },
        async {
            receiver.alloc(ot_count).unwrap();
            let output = receiver.queue_recv_rcot(ot_count).unwrap();
            receiver.flush(&mut ctx_receiver).await.unwrap();
            let _ = output.await.unwrap();
        }
    );

    // Ferret extends in whole LPN iterations, so it produces more than the
    // requested OT_COUNT. The surplus stays buffered after the request is
    // fulfilled, so the realized count is OT_COUNT plus what remains available.
    ot_count + sender.available()
}

/// Records receiver->sender messages for MT sender replay.
///
/// Runs on the process-wide `ThreadPool`.
pub async fn record_for_sender_mt(seed: u64, ot_count: usize) -> RecordedSenderMt {
    let mut rng = StdRng::seed_from_u64(seed);
    let delta: Block = rng.random();
    let cot_seed: Block = rng.random();
    let sender_seed: Block = rng.random();
    let receiver_seed: Block = rng.random();

    // exec_1 (receiver) is recorded, exec_0 (sender) receives
    let (mut exec_sender, mut exec_receiver, recorded) =
        recording_mt_context_with_limit(1024 * 1024, max_frame_length());

    let actual_count = run_protocol_record_receiver_mt(
        &mut exec_sender,
        &mut exec_receiver,
        bench_config(),
        delta,
        cot_seed,
        sender_seed,
        receiver_seed,
        ot_count,
    )
    .await;

    RecordedSenderMt {
        data: recorded.lock().unwrap().clone(),
        delta,
        cot_seed,
        sender_seed,
        actual_count,
    }
}

/// Builds an MT replay session for the sender on the process-wide thread pool.
pub fn replay_sender_mt(data: RecordedMtData) -> Session {
    replay_mt_context_with_limit(data, max_frame_length())
}

/// Runs MT sender only with replay context.
pub async fn run_sender_with_replay_mt(exec: &mut Session, data: &RecordedSenderMt) {
    let cot_send = IdealRCOTSender::new(data.cot_seed, data.delta);
    let mut sender = Sender::new(bench_config(), data.sender_seed, cot_send);

    let mut ctx = exec.new_context().unwrap();

    sender.alloc(OT_COUNT).unwrap();
    let output = sender.queue_send_rcot(OT_COUNT).unwrap();
    sender.flush(&mut ctx).await.unwrap();
    let _ = output.await.unwrap();
}
