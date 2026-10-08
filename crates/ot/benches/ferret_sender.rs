//! Isolated Ferret sender benchmark.
//!
//! Records protocol messages for replay-based isolated benchmarking of Ferret
//! sender.
//!
//! Run with: cargo bench -p mpz-ot --bench ferret_sender

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use futures::executor::block_on;
use mpz_common::{
    Flush, Session,
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

const OT_COUNT: usize = 10_000_000;

/// Calculate max frame length based on workload size.
fn max_frame_length() -> usize {
    // Ferret messages include SPCOT data which can be large
    // Use large buffer for production parameters
    64 * 1024 * 1024 // 64 MB
}

/// Creates the Ferret config for benchmarking.
fn bench_config() -> FerretConfig {
    FerretConfig::default()
}

/// Recorded data needed for deterministic replay.
struct RecordedData {
    /// Recorded bytes from receiver -> sender.
    bytes: Vec<u8>,
    /// Delta correlation.
    delta: Block,
    /// Seed for IdealRCOTSender.
    cot_seed: Block,
    /// Seed for Ferret sender.
    sender_seed: Block,
}

/// Runs the full Ferret protocol with sender and receiver.
/// Records receiver->sender messages.
async fn run_protocol_record_receiver(
    ctx_sender: &mut mpz_common::Context,
    ctx_receiver: &mut mpz_common::Context,
    config: FerretConfig,
    delta: Block,
    cot_seed: Block,
    sender_seed: Block,
    receiver_seed: Block,
) {
    let (cot_send, cot_recv) = ideal_rcot(cot_seed, delta);

    let mut sender = Sender::new(config.clone(), sender_seed, cot_send);
    let mut receiver = Receiver::new(config, receiver_seed, cot_recv);

    futures::join!(
        async {
            sender.alloc(OT_COUNT).unwrap();
            let output = sender.queue_send_rcot(OT_COUNT).unwrap();
            sender.flush(ctx_sender).await.unwrap();
            let _ = output.await.unwrap();
        },
        async {
            receiver.alloc(OT_COUNT).unwrap();
            let output = receiver.queue_recv_rcot(OT_COUNT).unwrap();
            receiver.flush(ctx_receiver).await.unwrap();
            let _ = output.await.unwrap();
        }
    );
}

/// Records receiver->sender messages for sender replay.
fn record_for_sender(seed: u64) -> RecordedData {
    block_on(async {
        let mut rng = StdRng::seed_from_u64(seed);
        let delta: Block = rng.random();
        let cot_seed: Block = rng.random();
        let sender_seed: Block = rng.random();
        let receiver_seed: Block = rng.random();

        // ctx_1 (receiver) is recorded, ctx_0 (sender) receives
        let (mut ctx_sender, mut ctx_receiver, recorded) =
            recording_st_context_with_limit(1024 * 1024, max_frame_length());

        let config = bench_config();

        run_protocol_record_receiver(
            &mut ctx_sender,
            &mut ctx_receiver,
            config,
            delta,
            cot_seed,
            sender_seed,
            receiver_seed,
        )
        .await;

        RecordedData {
            bytes: recorded.lock().unwrap().clone(),
            delta,
            cot_seed,
            sender_seed,
        }
    })
}

/// Runs sender only with replay context.
async fn run_sender_with_replay(ctx: &mut mpz_common::Context, data: &RecordedData) {
    let cot_send = IdealRCOTSender::new(data.cot_seed, data.delta);
    let config = bench_config();
    let mut sender = Sender::new(config, data.sender_seed, cot_send);

    sender.alloc(OT_COUNT).unwrap();
    let output = sender.queue_send_rcot(OT_COUNT).unwrap();
    sender.flush(ctx).await.unwrap();
    let _ = output.await.unwrap();
}

// ============================================================================
// Multi-threaded isolated sender benchmark
// ============================================================================

/// Recorded data needed for deterministic MT replay.
struct RecordedDataMt {
    /// Recorded bytes from receiver -> sender (per channel).
    data: RecordedMtData,
    /// Delta correlation.
    delta: Block,
    /// Seed for IdealRCOTSender.
    cot_seed: Block,
    /// Seed for Ferret sender.
    sender_seed: Block,
}

/// Runs the full Ferret protocol with MT contexts.
/// Records receiver->sender messages.
async fn run_protocol_record_receiver_mt(
    exec_sender: &mut Session,
    exec_receiver: &mut Session,
    config: FerretConfig,
    delta: Block,
    cot_seed: Block,
    sender_seed: Block,
    receiver_seed: Block,
) {
    let (cot_send, cot_recv) = ideal_rcot(cot_seed, delta);

    let mut sender = Sender::new(config.clone(), sender_seed, cot_send);
    let mut receiver = Receiver::new(config, receiver_seed, cot_recv);

    let mut ctx_sender = exec_sender.new_context().unwrap();
    let mut ctx_receiver = exec_receiver.new_context().unwrap();

    futures::join!(
        async {
            sender.alloc(OT_COUNT).unwrap();
            let output = sender.queue_send_rcot(OT_COUNT).unwrap();
            sender.flush(&mut ctx_sender).await.unwrap();
            let _ = output.await.unwrap();
        },
        async {
            receiver.alloc(OT_COUNT).unwrap();
            let output = receiver.queue_recv_rcot(OT_COUNT).unwrap();
            receiver.flush(&mut ctx_receiver).await.unwrap();
            let _ = output.await.unwrap();
        }
    );
}

/// Records receiver->sender messages for MT sender replay.
fn record_for_sender_mt(seed: u64) -> RecordedDataMt {
    block_on(async {
        let mut rng = StdRng::seed_from_u64(seed);
        let delta: Block = rng.random();
        let cot_seed: Block = rng.random();
        let sender_seed: Block = rng.random();
        let receiver_seed: Block = rng.random();

        // exec_1 (receiver) is recorded, exec_0 (sender) receives
        let (mut exec_sender, mut exec_receiver, recorded) =
            recording_mt_context_with_limit(1024 * 1024, max_frame_length());

        let config = bench_config();

        run_protocol_record_receiver_mt(
            &mut exec_sender,
            &mut exec_receiver,
            config,
            delta,
            cot_seed,
            sender_seed,
            receiver_seed,
        )
        .await;

        let data = recorded.lock().unwrap().clone();
        for (id, bytes) in &data.channels {
            println!("  Channel {:?}: {} bytes", id, bytes.len());
        }

        RecordedDataMt {
            data,
            delta,
            cot_seed,
            sender_seed,
        }
    })
}

/// Runs MT sender only with replay context.
async fn run_sender_with_replay_mt(exec: &mut Session, data: &RecordedDataMt) {
    let cot_send = IdealRCOTSender::new(data.cot_seed, data.delta);
    let config = bench_config();
    let mut sender = Sender::new(config, data.sender_seed, cot_send);

    let mut ctx = exec.new_context().unwrap();

    sender.alloc(OT_COUNT).unwrap();
    let output = sender.queue_send_rcot(OT_COUNT).unwrap();
    sender.flush(&mut ctx).await.unwrap();
    let _ = output.await.unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ferret_sender");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    group.throughput(Throughput::Elements(OT_COUNT as u64));

    // Record phase
    println!("Recording for Ferret sender...");
    let recorded = record_for_sender(0);
    println!("Recorded {} bytes", recorded.bytes.len());

    // Verify determinism
    let recorded_2 = record_for_sender(0);
    assert_eq!(
        recorded.bytes, recorded_2.bytes,
        "Ferret sender recordings not deterministic"
    );

    group.bench_function("ferret_sender", |b| {
        b.iter(|| {
            block_on(async {
                let mut ctx = replay_st_context(recorded.bytes.clone(), max_frame_length());
                run_sender_with_replay(&mut ctx, &recorded).await;
            })
        });
    });

    group.finish();

    // MT isolated sender benchmark
    let mut group_mt = c.benchmark_group("ferret_sender_mt");
    group_mt.sample_size(10);
    group_mt.measurement_time(std::time::Duration::from_secs(10));
    group_mt.throughput(Throughput::Elements(OT_COUNT as u64));

    println!("Recording for MT Ferret sender...");
    let recorded_mt = record_for_sender_mt(0);
    let total_bytes: usize = recorded_mt.data.channels.values().map(|v| v.len()).sum();
    println!(
        "Recorded {} channels, {} total bytes",
        recorded_mt.data.channels.len(),
        total_bytes
    );

    // Verify determinism
    let recorded_mt_2 = record_for_sender_mt(0);
    assert_eq!(
        recorded_mt
            .data
            .channels
            .keys()
            .collect::<std::collections::HashSet<_>>(),
        recorded_mt_2
            .data
            .channels
            .keys()
            .collect::<std::collections::HashSet<_>>(),
        "MT Ferret sender recordings have different channels"
    );
    for (id, data) in &recorded_mt.data.channels {
        assert_eq!(
            data,
            recorded_mt_2.data.channels.get(id).unwrap(),
            "MT Ferret sender recordings not deterministic for channel {:?}",
            id
        );
    }

    group_mt.bench_function("ferret_sender_mt", |b| {
        b.iter(|| {
            block_on(async {
                let mut exec =
                    replay_mt_context_with_limit(recorded_mt.data.clone(), max_frame_length());
                run_sender_with_replay_mt(&mut exec, &recorded_mt).await;
            })
        });
    });

    group_mt.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
