//! Test utilities.

use mpz_common::{Flush, context::test_st_context};
use mpz_core::Block;
use mpz_ot_core::{
    cot::{COTReceiver, COTSender},
    ot::{OTReceiver, OTSender},
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
    rot::{ROTReceiver, ROTReceiverOutput, ROTSender, ROTSenderOutput},
    test::{assert_cot, assert_ot, assert_rot},
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

/// Tests OT functionality.
pub async fn test_ot<S, R>(mut sender: S, mut receiver: R, cycles: usize)
where
    S: OTSender<Block> + Flush,
    R: OTReceiver<bool, Block> + Flush,
{
    let (mut sender_ctx, mut receiver_ctx) = test_st_context(8);

    let mut rng = StdRng::seed_from_u64(0);
    let msgs = (0..128)
        .map(|_| [rng.random(), rng.random()])
        .collect::<Vec<_>>();
    let choices = (0..128).map(|_| rng.random()).collect::<Vec<_>>();

    for _ in 0..cycles {
        let (output_sender, output_receiver) = futures::join! {
            async {
                sender.alloc(msgs.len()).unwrap();
                let output = sender.queue_send_ot(&msgs).unwrap();
                sender.flush(&mut sender_ctx).await.unwrap();
                output.await.unwrap()
            },
            async {
                receiver.alloc(choices.len()).unwrap();
                let output = receiver.queue_recv_ot(&choices).unwrap();
                receiver.flush(&mut receiver_ctx).await.unwrap();
                output.await.unwrap()
            }
        };

        assert_eq!(output_sender.id, output_receiver.id);
        assert_ot(&choices, &msgs, &output_receiver.msgs);
    }
}

/// Tests RCOT functionality.
pub async fn test_rcot<S, R>(mut sender: S, mut receiver: R, count: usize, cycles: usize)
where
    S: RCOTSender<Block> + Flush,
    R: RCOTReceiver<bool, Block> + Flush,
{
    let (mut sender_ctx, mut receiver_ctx) = test_st_context(8);

    for _ in 0..cycles {
        let (
            RCOTSenderOutput {
                id: sender_id,
                keys,
            },
            RCOTReceiverOutput {
                id: receiver_id,
                choices,
                msgs,
            },
        ) = futures::join! {
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
        };

        assert_eq!(sender_id, receiver_id);
        assert_cot(sender.delta(), &choices, &keys, &msgs);
    }
}

/// Tests COT functionality.
pub async fn test_cot<S, R>(mut sender: S, mut receiver: R, cycles: usize)
where
    S: COTSender<Block> + Flush,
    R: COTReceiver<bool, Block> + Flush,
{
    let (mut sender_ctx, mut receiver_ctx) = test_st_context(8);

    let mut rng = StdRng::seed_from_u64(0);
    let keys = (0..128).map(|_| rng.random()).collect::<Vec<_>>();
    let choices = (0..128).map(|_| rng.random()).collect::<Vec<_>>();

    for _ in 0..cycles {
        let (output_sender, output_receiver) = futures::join! {
            async {
                sender.alloc(keys.len()).unwrap();
                let output = sender.queue_send_cot(&keys).unwrap();
                sender.flush(&mut sender_ctx).await.unwrap();
                output.await.unwrap()
            },
            async {
                receiver.alloc(choices.len()).unwrap();
                let output = receiver.queue_recv_cot(&choices).unwrap();
                receiver.flush(&mut receiver_ctx).await.unwrap();
                output.await.unwrap()
            }
        };

        assert_eq!(output_sender.id, output_receiver.id);
        assert_cot(sender.delta(), &choices, &keys, &output_receiver.msgs);
    }
}

/// Tests ROT functionality.
pub async fn test_rot<S, R, T>(mut sender: S, mut receiver: R, cycles: usize)
where
    S: ROTSender<[T; 2]> + Flush,
    R: ROTReceiver<bool, T> + Flush,
    T: Copy + PartialEq,
{
    let (mut sender_ctx, mut receiver_ctx) = test_st_context(8);

    let count = 128;

    for _ in 0..cycles {
        let (
            ROTSenderOutput {
                id: sender_id,
                keys,
            },
            ROTReceiverOutput {
                id: receiver_id,
                choices,
                msgs,
            },
        ) = futures::join! {
            async {
                sender.alloc(count).unwrap();
                let output = sender.queue_send_rot(count).unwrap();
                sender.flush(&mut sender_ctx).await.unwrap();
                output.await.unwrap()
            },
            async {
                receiver.alloc(count).unwrap();
                let output = receiver.queue_recv_rot(count).unwrap();
                receiver.flush(&mut receiver_ctx).await.unwrap();
                output.await.unwrap()
            }
        };

        assert_eq!(sender_id, receiver_id);
        assert_rot(&choices, &keys, &msgs);
    }
}
