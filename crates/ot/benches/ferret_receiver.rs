//! Isolated Ferret receiver benchmark.
//!
//! Records protocol messages for replay-based isolated benchmarking of Ferret
//! receiver.
//!
//! Run with: cargo bench -p mpz-ot --bench ferret_receiver

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
    ideal::rcot::{IdealRCOTReceiver, ideal_rcot},
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
    /// Recorded bytes from sender -> receiver.
    bytes: Vec<u8>,
    /// Seed for IdealRCOTReceiver.
    cot_recv_seed: u64,
    /// Seed for Ferret receiver.
    receiver_seed: Block,
}

/// Runs the full Ferret protocol with sender and receiver.
/// Records sender->receiver messages (ctx_sender is the recording context).
async fn run_protocol_record_sender(
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

/// Records sender->receiver messages for receiver replay.
fn record_for_receiver(seed: u64) -> RecordedData {
    block_on(async {
        let mut rng = StdRng::seed_from_u64(seed);
        let delta: Block = rng.random();
        let cot_seed: Block = rng.random();
        let sender_seed: Block = rng.random();
        let receiver_seed: Block = rng.random();

        // ctx_0 (receiver) receives, ctx_1 (sender) is recorded
        let (mut ctx_receiver, mut ctx_sender, recorded) =
            recording_st_context_with_limit(1024 * 1024, max_frame_length());

        let config = bench_config();

        run_protocol_record_sender(
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
            cot_recv_seed: seed, // Use same seed for deterministic IdealRCOTReceiver
            receiver_seed,
        }
    })
}

/// Runs receiver only with replay context.
async fn run_receiver_with_replay(ctx: &mut mpz_common::Context, data: &RecordedData) {
    let cot_recv = IdealRCOTReceiver::from_seed(data.cot_recv_seed);
    let config = bench_config();
    let mut receiver = Receiver::new(config, data.receiver_seed, cot_recv);

    receiver.alloc(OT_COUNT).unwrap();
    let output = receiver.queue_recv_rcot(OT_COUNT).unwrap();
    receiver.flush(ctx).await.unwrap();
    let _ = output.await.unwrap();
}

// ============================================================================
// Multi-threaded isolated receiver benchmark
// ============================================================================

/// Recorded data needed for deterministic MT replay.
struct RecordedDataMt {
    /// Recorded bytes from sender -> receiver (per channel).
    data: RecordedMtData,
    /// Seed for IdealRCOTReceiver.
    cot_recv_seed: u64,
    /// Seed for Ferret receiver.
    receiver_seed: Block,
}

/// Runs the full Ferret protocol with MT contexts.
/// Records sender->receiver messages.
async fn run_protocol_record_sender_mt(
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

/// Records sender->receiver messages for MT receiver replay.
fn record_for_receiver_mt(seed: u64) -> RecordedDataMt {
    block_on(async {
        let mut rng = StdRng::seed_from_u64(seed);
        let delta: Block = rng.random();
        let cot_seed: Block = rng.random();
        let sender_seed: Block = rng.random();
        let receiver_seed: Block = rng.random();

        // exec_0 (receiver) receives, exec_1 (sender) is recorded
        let (mut exec_receiver, mut exec_sender, recorded) =
            recording_mt_context_with_limit(1024 * 1024, max_frame_length());

        let config = bench_config();

        run_protocol_record_sender_mt(
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
            cot_recv_seed: seed,
            receiver_seed,
        }
    })
}

/// Runs MT receiver only with replay context.
async fn run_receiver_with_replay_mt(exec: &mut Session, data: &RecordedDataMt) {
    let cot_recv = IdealRCOTReceiver::from_seed(data.cot_recv_seed);
    let config = bench_config();
    let mut receiver = Receiver::new(config, data.receiver_seed, cot_recv);

    let mut ctx = exec.new_context().unwrap();

    receiver.alloc(OT_COUNT).unwrap();
    let output = receiver.queue_recv_rcot(OT_COUNT).unwrap();
    receiver.flush(&mut ctx).await.unwrap();
    let _ = output.await.unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ferret_receiver");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    group.throughput(Throughput::Elements(OT_COUNT as u64));

    // Record phase
    println!("Recording for Ferret receiver...");
    let recorded = record_for_receiver(0);
    println!("Recorded {} bytes", recorded.bytes.len());

    // Verify determinism
    let recorded_2 = record_for_receiver(0);
    assert_eq!(
        recorded.bytes, recorded_2.bytes,
        "Ferret receiver recordings not deterministic"
    );

    group.bench_function("ferret_receiver", |b| {
        b.iter(|| {
            block_on(async {
                let mut ctx = replay_st_context(recorded.bytes.clone(), max_frame_length());
                run_receiver_with_replay(&mut ctx, &recorded).await;
            })
        });
    });

    group.finish();

    // MT isolated receiver benchmark
    let mut group_mt = c.benchmark_group("ferret_receiver_mt");
    group_mt.sample_size(10);
    group_mt.measurement_time(std::time::Duration::from_secs(10));
    group_mt.throughput(Throughput::Elements(OT_COUNT as u64));

    println!("Recording for MT Ferret receiver...");
    let recorded_mt = record_for_receiver_mt(0);
    let total_bytes: usize = recorded_mt.data.channels.values().map(|v| v.len()).sum();
    println!(
        "Recorded {} channels, {} total bytes",
        recorded_mt.data.channels.len(),
        total_bytes
    );

    // Verify determinism
    let recorded_mt_2 = record_for_receiver_mt(0);
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
        "MT Ferret receiver recordings have different channels"
    );
    for (id, data) in &recorded_mt.data.channels {
        assert_eq!(
            data,
            recorded_mt_2.data.channels.get(id).unwrap(),
            "MT Ferret receiver recordings not deterministic for channel {:?}",
            id
        );
    }

    group_mt.bench_function("ferret_receiver_mt", |b| {
        b.iter(|| {
            block_on(async {
                let mut exec =
                    replay_mt_context_with_limit(recorded_mt.data.clone(), max_frame_length());
                run_receiver_with_replay_mt(&mut exec, &recorded_mt).await;
            })
        });
    });

    group_mt.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
