//! Implementation of the Single-Point COT (spcot) protocol in the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) paper.

mod receiver;
mod sender;

pub(crate) use receiver::{SPCOTReceiver, SPCOTReceiverError};
pub(crate) use sender::{SPCOTSender, SPCOTSenderError};

use cfg_if::cfg_if;
#[cfg(feature = "rayon")]
use rayon::prelude::*;

use mpz_core::{Block, aes::AesEncryptor};
use mpz_fields::{ExtensionField, Field, gf2::Gf2, gf2_128::Gf2_128};

#[cfg(test)]
use rand::RngExt as _;

/// Monomial basis `[X^0, …, X^127]` of `GF(2^128)` over `GF(2)`.
pub(crate) const MONOMIAL: &[Gf2_128] = <Gf2_128 as ExtensionField<Gf2>>::MONOMIAL_BASIS;

/// Number of consistency check challenges per PRG stream in [`fold_chis`].
const CHI_CHUNK_SIZE: usize = 1 << 16;

/// Challenges generated per AES batch within a stream. Sized to keep the
/// scratch buffer on the stack.
const CHI_BATCH_SIZE: usize = 1 << 10;

/// Folds the consistency check challenges χ with the given values.
///
/// Returns `(Σᵢ χᵢ ⋅ values[i], Σᵢ ∈ picks χᵢ)`.
///
/// The challenges are derived from `seed` with the same construction as
/// [`Prg`](mpz_core::prg::Prg): challenge `j` of stream `i` is
/// `AES_seed(j || i)`, with each chunk of `CHI_CHUNK_SIZE` challenges on its
/// own stream. The fold therefore parallelizes deterministically — the
/// challenges depend only on the seed, not on the number of threads or
/// whether `rayon` is enabled — and the challenges are generated on the fly,
/// never materialized.
///
/// # Panics
///
/// Panics if `picks` is not sorted in ascending order.
pub(crate) fn fold_chis(seed: Block, values: &[Gf2_128], picks: &[usize]) -> (Gf2_128, Gf2_128) {
    assert!(picks.is_sorted(), "picks must be sorted");

    let aes = AesEncryptor::new(seed.to_bytes());

    let fold_chunk = |(i, chunk): (usize, &[Gf2_128])| {
        let stream = (i as u64).to_le_bytes();
        let start = i * CHI_CHUNK_SIZE;

        // The picks that fall into this chunk.
        let lo = picks.partition_point(|&p| p < start);
        let hi = picks.partition_point(|&p| p < start + chunk.len());
        let mut picks = picks[lo..hi].iter().peekable();

        let mut folded = Gf2_128::ZERO;
        let mut picked = Gf2_128::ZERO;
        let mut chis = [Gf2_128::ZERO; CHI_BATCH_SIZE];
        for (j, values) in chunk.chunks(CHI_BATCH_SIZE).enumerate() {
            let base = start + j * CHI_BATCH_SIZE;
            let chis = &mut chis[..values.len()];

            // chi = AES_seed(counter || stream), matching the PRG stream
            // construction.
            let blocks: &mut [[u8; 16]] = zerocopy::transmute_mut!(&mut *chis);
            for (k, block) in blocks.iter_mut().enumerate() {
                block[..8].copy_from_slice(&((j * CHI_BATCH_SIZE + k) as u64).to_le_bytes());
                block[8..].copy_from_slice(&stream);
            }
            aes.encrypt_blocks(blocks);

            folded = folded + Gf2_128::inner_product(chis, values);

            while let Some(&&pick) = picks.peek() {
                if pick >= base + values.len() {
                    break;
                }
                picked = picked + chis[pick - base];
                picks.next();
            }
        }

        (folded, picked)
    };

    #[allow(clippy::let_and_return)]
    let folded = {
        cfg_if! {
            if #[cfg(feature = "rayon")] {
                values
                    .par_chunks(CHI_CHUNK_SIZE)
                    .enumerate()
                    .map(fold_chunk)
                    .reduce(
                        || (Gf2_128::ZERO, Gf2_128::ZERO),
                        |a, b| (a.0 + b.0, a.1 + b.1),
                    )
            } else {
                values
                    .chunks(CHI_CHUNK_SIZE)
                    .enumerate()
                    .map(fold_chunk)
                    .fold((Gf2_128::ZERO, Gf2_128::ZERO), |a, b| {
                        (a.0 + b.0, a.1 + b.1)
                    })
            }
        }
    };

    folded
}

/// Generates ideal SPCOT outputs.
///
/// Returns the sender and receiver outputs, respectively.
#[cfg(test)]
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

    /// The chis must depend only on the seed: a party with `rayon` enabled
    /// must derive the same challenges as one without. This pins the
    /// streamed fold against a materialized PRG reference, which also covers
    /// the chunk-per-stream scheme.
    #[test]
    fn test_fold_chis_deterministic() {
        use mpz_core::prg::Prg;
        use rand::SeedableRng;
        use zerocopy::IntoBytes;

        let mut rng = StdRng::seed_from_u64(0);
        let seed = Block::ONES;
        let count = 2 * CHI_CHUNK_SIZE + 3 * CHI_BATCH_SIZE + 42;

        // Reference: materialize the challenges with the PRG.
        let mut chis = vec![Gf2_128::ZERO; count];
        for (i, chunk) in chis.chunks_mut(CHI_CHUNK_SIZE).enumerate() {
            let mut prg = Prg::from_seed(seed);
            prg.set_stream_id(i as u64);
            prg.random_bytes(chunk.as_mut_bytes());
        }

        let values: Vec<Gf2_128> = (0..count).map(|_| rng.random()).collect();
        let picks = vec![
            0,
            7,
            CHI_BATCH_SIZE,
            CHI_CHUNK_SIZE - 1,
            CHI_CHUNK_SIZE,
            count - 1,
        ];

        let expected_fold = Gf2_128::inner_product(&chis, &values);
        let expected_picked = picks.iter().fold(Gf2_128::ZERO, |acc, &p| acc + chis[p]);

        assert_eq!(
            fold_chis(seed, &values, &picks),
            (expected_fold, expected_picked)
        );
        assert_eq!(fold_chis(seed, &[], &[]), (Gf2_128::ZERO, Gf2_128::ZERO));
    }

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

        let total: usize = lengths.iter().map(|length| 1 << length).sum();
        let mut vs = vec![Gf2_128::ZERO; total];
        let mut ws = vec![Gf2_128::ZERO; total];

        let keys: Vec<Gf2_128> = keys.iter().map(|&key| key.into()).collect();
        let macs: Vec<Gf2_128> = macs.iter().map(|&mac| mac.into()).collect();

        let cs = sender
            .extend(rng, lengths, &keys, &derandomize.flip, &mut vs)
            .unwrap();
        receiver.extend(lengths, idxs, &macs, &cs, &mut ws).unwrap();

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

        let keys: Vec<Gf2_128> = keys.iter().map(|&key| key.into()).collect();
        let macs: Vec<Gf2_128> = macs.iter().map(|&mac| mac.into()).collect();

        let derandomize = receiver.start_check(&macs, &masks, &ws).unwrap();
        let hashed_v = sender.check(&keys, &derandomize.flip, &vs).unwrap();
        receiver.check(hashed_v).unwrap();

        assert!(!sender.wants_check());
        assert!(!receiver.wants_check());

        let vs: Vec<Block> = vs.into_iter().map(Block::from).collect();
        let ws: Vec<Block> = ws.into_iter().map(Block::from).collect();

        let spcot_lengths = lengths.iter().map(|length| 1 << length).collect::<Vec<_>>();
        for ((v, w), &idx) in slices_from_lengths(&vs, &spcot_lengths)
            .into_iter()
            .zip(slices_from_lengths(&ws, &spcot_lengths))
            .zip(idxs)
        {
            assert_spcot(sender.delta(), w, idx, v);
        }

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
