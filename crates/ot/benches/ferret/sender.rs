//! Isolated Ferret sender benchmark.
//!
//! The ST/MT protocol bodies live in `support/sender_body.rs`.
//!
//! Run with:
//!   cargo bench -p mpz-ot --bench ferret_sender                  (ST only)
//!   cargo bench -p mpz-ot --bench ferret_sender --features rayon (MT only)

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use futures::executor::block_on;
#[cfg(feature = "rayon")]
use std::collections::HashSet;

#[path = "support/sender_body.rs"]
#[allow(dead_code)] // The gated-out mode's body functions are unused.
mod body;

use body::OT_COUNT;

fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(not(feature = "rayon"))]
    {
        let mut group = c.benchmark_group("ferret");
        group.sample_size(10);
        group.measurement_time(std::time::Duration::from_secs(10));

        println!("Recording for Ferret sender...");
        let recorded = block_on(body::record_for_sender_st(0, OT_COUNT));
        println!("Recorded {} bytes", recorded.bytes.len());

        // Throughput is over the correlations actually produced, not OT_COUNT:
        // extension rounds up to whole LPN iterations.
        println!(
            "Requested {OT_COUNT} COTs, produced {} (whole-iteration rounding)",
            recorded.actual_count
        );
        group.throughput(Throughput::Elements(recorded.actual_count as u64));

        // Verify determinism.
        let recorded_2 = block_on(body::record_for_sender_st(0, OT_COUNT));
        assert_eq!(
            recorded.bytes, recorded_2.bytes,
            "Ferret sender recordings not deterministic"
        );

        group.bench_function("sender_st", |b| {
            b.iter_batched(
                || body::replay_sender_st(recorded.bytes.clone()),
                |mut ctx| block_on(body::run_sender_with_replay_st(&mut ctx, &recorded)),
                criterion::BatchSize::SmallInput,
            );
        });

        group.finish();
    }

    #[cfg(feature = "rayon")]
    {
        // MT isolated sender benchmark
        let mut group_mt = c.benchmark_group("ferret");
        group_mt.sample_size(10);
        group_mt.measurement_time(std::time::Duration::from_secs(10));

        println!("Recording for MT Ferret sender...");
        let recorded_mt = block_on(body::record_for_sender_mt(0, OT_COUNT));
        let total_bytes: usize = recorded_mt.data.channels.values().map(|v| v.len()).sum();
        println!(
            "Recorded {} channels, {} total bytes",
            recorded_mt.data.channels.len(),
            total_bytes
        );

        // Throughput is over the correlations actually produced, not OT_COUNT:
        // extension rounds up to whole LPN iterations.
        group_mt.throughput(Throughput::Elements(recorded_mt.actual_count as u64));

        // Verify determinism.
        let recorded_mt_2 = block_on(body::record_for_sender_mt(0, OT_COUNT));
        assert_eq!(
            recorded_mt.data.channels.keys().collect::<HashSet<_>>(),
            recorded_mt_2.data.channels.keys().collect::<HashSet<_>>(),
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

        group_mt.bench_function("sender_mt", |b| {
            b.iter_batched(
                || body::replay_sender_mt(recorded_mt.data.clone()),
                |mut exec| block_on(body::run_sender_with_replay_mt(&mut exec, &recorded_mt)),
                criterion::BatchSize::SmallInput,
            );
        });

        group_mt.finish();
    }
}
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
