//! Unit tests for recording and replay infrastructure.

use serio::{SinkExt, stream::IoStreamExt};

use crate::context::{Context, DEFAULT_CONCURRENCY_LIMIT};

use super::{
    recording::{recording_mt_context, recording_st_context},
    replay::replay_mt_context,
};

#[tokio::test]
async fn test_recording_st_context() {
    let (mut ctx_0, mut ctx_1, recorded) = recording_st_context(1024 * 1024);

    // Send a message from ctx_1 to ctx_0 (this should be recorded)
    ctx_1.io_mut().send(42u32).await.unwrap();
    ctx_1.io_mut().send(vec![1u8, 2, 3, 4]).await.unwrap();

    // Receive on ctx_0
    let msg1: u32 = ctx_0.io_mut().expect_next().await.unwrap();
    let msg2: Vec<u8> = ctx_0.io_mut().expect_next().await.unwrap();

    assert_eq!(msg1, 42);
    assert_eq!(msg2, vec![1, 2, 3, 4]);

    // Verify something was recorded
    let recorded_bytes = recorded.lock().unwrap();
    assert!(!recorded_bytes.is_empty(), "should have recorded bytes");
}

#[tokio::test]
async fn test_recording_determinism() {
    // Run the same protocol twice and verify recorded bytes are identical
    async fn run_protocol(ctx_0: &mut Context, ctx_1: &mut Context) {
        ctx_1.io_mut().send(123u64).await.unwrap();
        ctx_1.io_mut().send("hello".to_string()).await.unwrap();
        ctx_1.io_mut().send(vec![10u8; 100]).await.unwrap();

        let _: u64 = ctx_0.io_mut().expect_next().await.unwrap();
        let _: String = ctx_0.io_mut().expect_next().await.unwrap();
        let _: Vec<u8> = ctx_0.io_mut().expect_next().await.unwrap();
    }

    // First run
    let (mut ctx_0a, mut ctx_1a, recorded_a) = recording_st_context(1024 * 1024);
    run_protocol(&mut ctx_0a, &mut ctx_1a).await;

    // Second run
    let (mut ctx_0b, mut ctx_1b, recorded_b) = recording_st_context(1024 * 1024);
    run_protocol(&mut ctx_0b, &mut ctx_1b).await;

    // Verify recordings are identical
    let bytes_a = recorded_a.lock().unwrap();
    let bytes_b = recorded_b.lock().unwrap();
    assert_eq!(*bytes_a, *bytes_b, "recordings should be deterministic");
}

#[tokio::test]
async fn test_recording_mt_context() {
    let (exec_0, exec_1, recorded) = recording_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    // Send a message from ctx_1 to ctx_0 (this should be recorded)
    ctx_1.io_mut().send(42u32).await.unwrap();
    ctx_1.io_mut().send(vec![1u8, 2, 3, 4]).await.unwrap();

    // Receive on ctx_0
    let msg1: u32 = ctx_0.io_mut().expect_next().await.unwrap();
    let msg2: Vec<u8> = ctx_0.io_mut().expect_next().await.unwrap();

    assert_eq!(msg1, 42);
    assert_eq!(msg2, vec![1, 2, 3, 4]);

    // Verify something was recorded
    let recorded_data = recorded.lock().unwrap();
    assert!(
        !recorded_data.channels.is_empty(),
        "should have recorded channels"
    );

    // Check that the recorded channel has data
    let total_bytes: usize = recorded_data.channels.values().map(|v| v.len()).sum();
    assert!(total_bytes > 0, "should have recorded bytes");
}

#[tokio::test]
async fn test_replay_mt_context() {
    // First: record some messages
    let (exec_0, exec_1, recorded) = recording_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    // Send messages from ctx_1 (verifier) to ctx_0 (prover)
    ctx_1.io_mut().send(42u32).await.unwrap();
    ctx_1.io_mut().send("hello".to_string()).await.unwrap();

    // Receive on ctx_0
    let _: u32 = ctx_0.io_mut().expect_next().await.unwrap();
    let _: String = ctx_0.io_mut().expect_next().await.unwrap();

    // Get recorded data
    let recorded_data = recorded.lock().unwrap().clone();

    // Now replay to a new context
    let replay_exec = replay_mt_context(recorded_data);
    let mut replay_ctx = replay_exec.new_context().unwrap();

    // Should be able to receive the same messages from replay
    let msg1: u32 = replay_ctx.io_mut().expect_next().await.unwrap();
    let msg2: String = replay_ctx.io_mut().expect_next().await.unwrap();

    assert_eq!(msg1, 42);
    assert_eq!(msg2, "hello");
}

#[tokio::test]
async fn test_recording_mt_multiple_channels() {
    // Test that recording works correctly with multiple channels via
    // ctx.try_join()
    let (exec_0, exec_1, recorded) = recording_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    // Run both sides concurrently
    let (result, send_result) = futures::join!(
        // ctx_0 uses try_join to receive on multiple channels
        ctx_0.try_join(
            |ctx: &mut Context| Box::pin(async move {
                let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            }),
            |ctx: &mut Context| Box::pin(async move {
                let msg: u64 = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            }),
        ),
        // ctx_1 uses try_join to send on multiple channels
        ctx_1.try_join(
            |ctx: &mut Context| Box::pin(async move {
                ctx.io_mut().send(42u32).await.unwrap();
                Ok::<_, std::io::Error>(())
            }),
            |ctx: &mut Context| Box::pin(async move {
                ctx.io_mut().send(123u64).await.unwrap();
                Ok::<_, std::io::Error>(())
            }),
        )
    );

    let (msg_a, msg_b) = result.unwrap().unwrap();
    send_result.unwrap().unwrap();

    assert_eq!(msg_a, 42);
    assert_eq!(msg_b, 123);

    // Verify multiple channels were recorded
    let recorded_data = recorded.lock().unwrap();
    println!(
        "Recorded {} channels: {:?}",
        recorded_data.channels.len(),
        recorded_data.channels.keys().collect::<Vec<_>>()
    );

    // Should have more than 1 channel (main + at least one child)
    assert!(
        recorded_data.channels.len() > 1,
        "expected multiple channels, got {}",
        recorded_data.channels.len()
    );

    // Each channel should have some data
    for (id, bytes) in &recorded_data.channels {
        println!("Channel {:?}: {} bytes", id, bytes.len());
        assert!(!bytes.is_empty(), "channel {:?} should have data", id);
    }
}

#[tokio::test]
async fn test_recording_mt_try_join3() {
    let (exec_0, exec_1, recorded) = recording_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    let (result, send_result) = futures::join!(
        ctx_0.try_join3(
            |ctx: &mut Context| Box::pin(async move {
                let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            }),
            |ctx: &mut Context| Box::pin(async move {
                let msg: u64 = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            }),
            |ctx: &mut Context| Box::pin(async move {
                let msg: String = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            }),
        ),
        ctx_1.try_join3(
            |ctx: &mut Context| Box::pin(async move {
                ctx.io_mut().send(42u32).await.unwrap();
                Ok::<_, std::io::Error>(())
            }),
            |ctx: &mut Context| Box::pin(async move {
                ctx.io_mut().send(123u64).await.unwrap();
                Ok::<_, std::io::Error>(())
            }),
            |ctx: &mut Context| Box::pin(async move {
                ctx.io_mut().send("hello".to_string()).await.unwrap();
                Ok::<_, std::io::Error>(())
            }),
        )
    );

    let (msg_a, msg_b, msg_c) = result.unwrap().unwrap();
    send_result.unwrap().unwrap();

    assert_eq!(msg_a, 42);
    assert_eq!(msg_b, 123);
    assert_eq!(msg_c, "hello");

    let recorded_data = recorded.lock().unwrap();
    println!(
        "try_join3: Recorded {} channels: {:?}",
        recorded_data.channels.len(),
        recorded_data.channels.keys().collect::<Vec<_>>()
    );

    // Should have 3 channels (one per fork)
    assert!(
        recorded_data.channels.len() >= 3,
        "expected at least 3 channels, got {}",
        recorded_data.channels.len()
    );
}

#[tokio::test]
async fn test_recording_mt_try_join4() {
    let (exec_0, exec_1, recorded) = recording_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    let (result, send_result) = futures::join!(
        ctx_0.try_join4(
            |ctx: &mut Context| Box::pin(async move {
                let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            }),
            |ctx: &mut Context| Box::pin(async move {
                let msg: u64 = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            }),
            |ctx: &mut Context| Box::pin(async move {
                let msg: String = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            }),
            |ctx: &mut Context| Box::pin(async move {
                let msg: Vec<u8> = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            }),
        ),
        ctx_1.try_join4(
            |ctx: &mut Context| Box::pin(async move {
                ctx.io_mut().send(42u32).await.unwrap();
                Ok::<_, std::io::Error>(())
            }),
            |ctx: &mut Context| Box::pin(async move {
                ctx.io_mut().send(123u64).await.unwrap();
                Ok::<_, std::io::Error>(())
            }),
            |ctx: &mut Context| Box::pin(async move {
                ctx.io_mut().send("hello".to_string()).await.unwrap();
                Ok::<_, std::io::Error>(())
            }),
            |ctx: &mut Context| Box::pin(async move {
                ctx.io_mut().send(vec![1u8, 2, 3]).await.unwrap();
                Ok::<_, std::io::Error>(())
            }),
        )
    );

    let (msg_a, msg_b, msg_c, msg_d) = result.unwrap().unwrap();
    send_result.unwrap().unwrap();

    assert_eq!(msg_a, 42);
    assert_eq!(msg_b, 123);
    assert_eq!(msg_c, "hello");
    assert_eq!(msg_d, vec![1u8, 2, 3]);

    let recorded_data = recorded.lock().unwrap();
    println!(
        "try_join4: Recorded {} channels: {:?}",
        recorded_data.channels.len(),
        recorded_data.channels.keys().collect::<Vec<_>>()
    );

    assert!(
        recorded_data.channels.len() >= 4,
        "expected at least 4 channels, got {}",
        recorded_data.channels.len()
    );
}

#[tokio::test]
async fn test_recording_mt_map() {
    let (exec_0, exec_1, recorded) = recording_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    // Create items to map over
    let items: Vec<u32> = (0..8).collect();

    let (recv_results, send_results) = futures::join!(
        ctx_0.map(items.clone(), |ctx: &mut Context, _item: u32| Box::pin(
            async move {
                let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                msg
            }
        ),),
        ctx_1.map(items, |ctx: &mut Context, item: u32| Box::pin(async move {
            ctx.io_mut().send(item * 10).await.unwrap();
        }),)
    );

    let recv_results = recv_results.unwrap();
    send_results.unwrap();

    // Results should be [0, 10, 20, 30, 40, 50, 60, 70] (order may vary)
    let mut sorted_results = recv_results.clone();
    sorted_results.sort();
    assert_eq!(sorted_results, vec![0, 10, 20, 30, 40, 50, 60, 70]);

    let recorded_data = recorded.lock().unwrap();
    println!(
        "map: Recorded {} channels: {:?}",
        recorded_data.channels.len(),
        recorded_data.channels.keys().collect::<Vec<_>>()
    );

    // Should have multiple channels (distributed across workers)
    assert!(
        recorded_data.channels.len() > 1,
        "expected multiple channels from map, got {}",
        recorded_data.channels.len()
    );
}

#[tokio::test]
async fn test_recording_mt_nested_try_join() {
    let (exec_0, exec_1, recorded) = recording_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    let (result, send_result) = futures::join!(
        // Outer try_join
        ctx_0.try_join(
            // Inner try_join in first branch
            |ctx: &mut Context| Box::pin(async move {
                // Receive the outer child's message first
                let outer_msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                assert_eq!(outer_msg, 999);
                let inner_result = ctx
                    .try_join(
                        |ctx: &mut Context| {
                            Box::pin(async move {
                                let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                                Ok::<_, std::io::Error>(msg)
                            })
                        },
                        |ctx: &mut Context| {
                            Box::pin(async move {
                                let msg: u64 = ctx.io_mut().expect_next().await.unwrap();
                                Ok::<_, std::io::Error>(msg)
                            })
                        },
                    )
                    .await
                    .unwrap()
                    .unwrap();
                Ok::<_, std::io::Error>(inner_result)
            }),
            // Simple receive in second branch
            |ctx: &mut Context| Box::pin(async move {
                let msg: String = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            }),
        ),
        // Matching structure on sender side
        ctx_1.try_join(
            |ctx: &mut Context| Box::pin(async move {
                // Write something on outer child before inner try_join
                ctx.io_mut().send(999u32).await.unwrap();
                ctx.try_join(
                    |ctx: &mut Context| {
                        Box::pin(async move {
                            ctx.io_mut().send(42u32).await.unwrap();
                            Ok::<_, std::io::Error>(())
                        })
                    },
                    |ctx: &mut Context| {
                        Box::pin(async move {
                            ctx.io_mut().send(123u64).await.unwrap();
                            Ok::<_, std::io::Error>(())
                        })
                    },
                )
                .await
                .unwrap()
                .unwrap();
                Ok::<_, std::io::Error>(())
            }),
            |ctx: &mut Context| Box::pin(async move {
                ctx.io_mut().send("nested".to_string()).await.unwrap();
                Ok::<_, std::io::Error>(())
            }),
        )
    );

    let ((msg_a, msg_b), msg_c) = result.unwrap().unwrap();
    send_result.unwrap().unwrap();

    assert_eq!(msg_a, 42);
    assert_eq!(msg_b, 123);
    assert_eq!(msg_c, "nested");

    let recorded_data = recorded.lock().unwrap();
    println!(
        "nested: Recorded {} channels: {:?}",
        recorded_data.channels.len(),
        recorded_data.channels.keys().collect::<Vec<_>>()
    );

    // Should have at least 4 channels (outer 2 + inner 2)
    assert!(
        recorded_data.channels.len() >= 4,
        "expected at least 4 channels from nested try_join, got {}",
        recorded_data.channels.len()
    );
}

#[tokio::test]
async fn test_map_respects_concurrency_limit() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    const LIMIT: usize = 3;

    let (mux, _peer) = crate::mux::test_framed_mux(1024);
    let session = crate::session::SessionBuilder::default()
        .cooperative()
        .concurrency_limit(LIMIT)
        .build(mux)
        .unwrap();
    let mut ctx = session.new_context().unwrap();

    // Tracks how many item futures are running at once and the peak observed.
    let active = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));

    let items: Vec<u32> = (0..12).collect();
    let results = ctx
        .map(items, {
            let active = active.clone();
            let max_seen = max_seen.clone();
            move |_ctx: &mut Context, item: u32| {
                let active = active.clone();
                let max_seen = max_seen.clone();
                Box::pin(async move {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(now, Ordering::SeqCst);
                    // Yield repeatedly so concurrently-buffered futures overlap
                    // before any of them completes.
                    for _ in 0..8 {
                        tokio::task::yield_now().await;
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                    item
                })
            }
        })
        .await
        .unwrap();

    // Results are returned in input order regardless of the bound.
    assert_eq!(results, (0..12).collect::<Vec<_>>());
    // Concurrency never exceeded the limit, and reached it (more items than the
    // limit, so the window is fully utilized).
    assert_eq!(max_seen.load(Ordering::SeqCst), LIMIT);
}

/// Two parties mapping far more items than the concurrency limit must stay in
/// lockstep: both sides derive the same lanes, and results come back in input
/// order regardless of which lane handled which item.
#[tokio::test]
async fn test_recording_mt_map_beyond_concurrency_limit() {
    let (session_0, session_1, recorded) = recording_mt_context(1024 * 1024);

    let mut ctx_0 = session_0.new_context().unwrap();
    let mut ctx_1 = session_1.new_context().unwrap();

    // Far more items than the concurrency limit.
    let items: Vec<u32> = (0..(DEFAULT_CONCURRENCY_LIMIT as u32 * 3 + 1)).collect();

    let (recv_results, send_results) = futures::join!(
        ctx_0.map(items.clone(), |ctx: &mut Context, _item: u32| Box::pin(
            async move {
                let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                msg
            }
        )),
        ctx_1.map(items.clone(), |ctx: &mut Context, item: u32| Box::pin(
            async move {
                ctx.io_mut().send(item * 10).await.unwrap();
            }
        ))
    );

    let recv_results = recv_results.unwrap();
    send_results.unwrap();

    assert_eq!(
        recv_results,
        items.iter().map(|item| item * 10).collect::<Vec<_>>()
    );

    // Channel usage is bounded by the lane count rather than growing with the
    // number of items, which would exhaust the multiplexer's channel budget.
    let recorded_data = recorded.lock().unwrap();
    assert_eq!(
        recorded_data.channels.len(),
        DEFAULT_CONCURRENCY_LIMIT,
        "map must not open more than one channel per lane"
    );
}
