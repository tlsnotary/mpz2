//! Implementation of the Single-Point COT (spcot) protocol in the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) paper.

mod receiver;
mod sender;

pub(crate) use receiver::{SPCOTReceiver, SPCOTReceiverError};
pub(crate) use sender::{SPCOTSender, SPCOTSenderError};

#[cfg(test)]
use mpz_core::Block;
#[cfg(test)]
use rand::RngExt as _;

#[cfg(test)]
/// Generates ideal SPCOT outputs.
///
/// Returns the sender and receiver outputs, respectively.
pub(crate) fn spcot<R: rand::Rng>(
    rng: &mut R,
    lengths: &[usize],
    idxs: &[usize],
    delta: Block,
) -> (Vec<Block>, Vec<Block>) {
    assert_eq!(lengths.len(), idxs.len());

    let total_length = lengths.iter().map(|length| 1 << length).sum();
    let vs: Vec<Block> = (0..total_length).map(|_| rng.random()).collect();
    let mut ws = vs.clone();

    let mut i = 0;
    for (&idx, &length) in idxs.iter().zip(lengths) {
        ws[i + idx] ^= delta;
        i += 1 << length;
    }

    (vs, ws)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ferret::config::CSP,
        ideal::rcot::IdealRCOT,
        rcot::{RCOTReceiverOutput, RCOTSenderOutput},
        test::assert_spcot,
    };
    use mpz_core::utils::slices_from_lengths;
    use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

    fn execute<R: Rng>(
        rng: &mut R,
        sender: &mut SPCOTSender,
        receiver: &mut SPCOTReceiver,
        lengths: &[usize],
        idxs: &[usize],
    ) -> (Vec<Block>, Vec<Block>) {
        let len_sum: usize = lengths.iter().sum();

        let mut cot = IdealRCOT::new(rng.random(), sender.delta());
        cot.alloc(len_sum + CSP);
        cot.flush().unwrap();

        let (
            RCOTSenderOutput { keys, .. },
            RCOTReceiverOutput {
                choices: masks,
                msgs: macs,
                ..
            },
        ) = cot.transfer(len_sum).unwrap();

        let derandomize = receiver.derandomize(lengths, idxs, &masks).unwrap();

        let (vs, ms, sums) = sender
            .extend(rng, lengths, &keys, &derandomize.flip)
            .unwrap();
        let ws = receiver.extend(lengths, idxs, &macs, &ms, &sums).unwrap();

        let vs = vs.to_vec();
        let ws = ws.to_vec();

        let spcot_lengths = lengths.iter().map(|length| 1 << length).collect::<Vec<_>>();
        for ((v, w), &idx) in slices_from_lengths(&vs, &spcot_lengths)
            .into_iter()
            .zip(slices_from_lengths(&ws, &spcot_lengths))
            .zip(idxs)
        {
            assert_spcot(sender.delta(), w, idx, v);
        }

        assert!(sender.wants_check());
        assert!(receiver.wants_check());

        let (
            RCOTSenderOutput { keys, .. },
            RCOTReceiverOutput {
                choices: masks,
                msgs: macs,
                ..
            },
        ) = cot.transfer(CSP).unwrap();

        let derandomize = receiver.start_check(&macs, &masks).unwrap();
        let hashed_v = sender.check(&keys, &derandomize.flip).unwrap();
        receiver.check(hashed_v).unwrap();

        assert!(!sender.wants_check());
        assert!(!receiver.wants_check());

        (vs, ws)
    }

    #[test]
    fn test_spcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = rng.random();

        let mut sender = SPCOTSender::new(delta);
        let mut receiver = SPCOTReceiver::new();

        // Execute twice.
        for _ in 0..2 {
            let lengths: Vec<usize> = (1..8).collect();
            let idxs: Vec<usize> = (1..8).map(|n| rng.random_range(0..1 << n)).collect();
            execute(&mut rng, &mut sender, &mut receiver, &lengths, &idxs);
        }
    }

    #[test]
    fn test_ideal_spcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = rng.random();

        let idxs: Vec<_> = (0..8).map(|n| rng.random_range(0..1 << n)).collect();
        let lengths: Vec<_> = (0..8).collect();

        let (vs, ws) = spcot(&mut rng, &lengths, &idxs, delta);

        assert_eq!(vs.len(), ws.len());

        let mut i = 0;
        for (&idx, &length) in idxs.iter().zip(&lengths) {
            let length = 1 << length;
            let v = &vs[i..i + length];
            let w = &ws[i..i + length];

            assert_spcot(delta, w, idx, v);

            i += length;
        }
    }
}
