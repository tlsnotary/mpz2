mod receiver;
mod sender;

pub(crate) use receiver::{MPCOTReceiver, MPCOTReceiverError, state as receiver_state};
pub(crate) use sender::{MPCOTSender, MPCOTSenderError, state as sender_state};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ferret::spcot::spcot;
    use mpz_core::lpn::{LpnType, sample_error_indices};
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use rstest::*;

    #[rstest]
    #[case::uniform(LpnType::Uniform)]
    #[case::regular(LpnType::Regular)]
    fn test_mpcot(#[case] lpn_type: LpnType) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = rng.random();
        let cuckoo_seed = rng.random();

        let sender = MPCOTSender::new(cuckoo_seed, lpn_type);
        let receiver = MPCOTReceiver::new(cuckoo_seed, lpn_type);

        let n = 10;
        let indices = sample_error_indices(&mut rng, lpn_type, n, 5);

        let (sender, sender_lengths) = sender.start_extend(indices.len(), 10).unwrap();
        let (receiver, receiver_lengths, receiver_idxs) =
            receiver.start_extend(&indices, n).unwrap();

        assert_eq!(sender_lengths, receiver_lengths);

        let (vs, ws) = spcot(&mut rng, &sender_lengths, &receiver_idxs, delta);

        let sender_output = sender.extend(&vs).unwrap();
        let mut receiver_output = receiver.extend(&ws).unwrap();

        for idx in indices {
            receiver_output[idx] ^= delta;
        }

        assert_eq!(sender_output, receiver_output);
    }
}
