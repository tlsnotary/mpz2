use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use futures::future::join_all;
use mpz_common::{Flush, context::test_st_context};
use mpz_core::Block;
use mpz_ot::{
    ideal::rcot::ideal_rcot,
    rcot::{
        RCOTReceiverOutput, RCOTSenderOutput,
        shared::{SharedRCOTReceiver, SharedRCOTSender},
    },
};
use mpz_ot_core::rcot::{RCOTReceiver, RCOTSender};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::hint::black_box;
use tokio::runtime::Runtime;

fn shared(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("shared");
    for n in [100_000, 1_000_000, 10_000_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let mut rng = ChaCha12Rng::seed_from_u64(0);

            b.iter(|| {
                rt.block_on(async {
                    let (ideal_send, ideal_recv) =
                        ideal_rcot(Block::random(&mut rng), Block::random(&mut rng));

                    let sender = SharedRCOTSender::new(ideal_send);
                    let receiver = SharedRCOTReceiver::new(ideal_recv);

                    let mut senders = vec![sender];
                    let mut receivers = vec![receiver];
                    for _ in 1..3 {
                        senders.push(senders[0].clone());
                        receivers.push(receivers[0].clone());
                    }

                    let tasks: Vec<_> = senders
                        .into_iter()
                        .zip(receivers)
                        .map(|(send, recv)| tokio::spawn(run_rcot(send, recv, n)))
                        .collect();

                    let results =
                        join_all(tasks.into_iter().map(|task| async { task.await.unwrap() })).await;

                    black_box(results);
                });
            });
        });
    }
}

/// Runs RCOT functionality.
pub async fn run_rcot<S, R>(
    mut sender: S,
    mut receiver: R,
    count: usize,
) -> (RCOTSenderOutput<Block>, RCOTReceiverOutput<bool, Block>)
where
    S: RCOTSender<Block> + Flush,
    R: RCOTReceiver<bool, Block> + Flush,
{
    let (mut sender_ctx, mut receiver_ctx) = test_st_context(8);

    futures::join! {
        async {
            sender.alloc(count).unwrap();
            let output = sender.queue_send_rcot(count).unwrap();
            sender.flush(&mut sender_ctx).await.unwrap();
            output.await.unwrap()
        },
        async {
            receiver.alloc(count).unwrap();
            let output = receiver.queue_recv_rcot(count).unwrap();
            receiver.flush(&mut receiver_ctx).await.unwrap();
            output.await.unwrap()
        }
    }
}

criterion_group! {
    name = shared_benches;
    config = Criterion::default().sample_size(10);
    targets = shared
}

criterion_main!(shared_benches);
