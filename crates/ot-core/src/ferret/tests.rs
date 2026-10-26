use super::*;
use crate::{
    ferret::config::TEST_PARAMS,
    ideal::rcot::IdealRCOT,
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
    test::assert_cot,
};
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn test_ferret() {
    use rand::Rng;

    let mut rng = StdRng::seed_from_u64(0);
    let delta = rng.random();
    let cot = IdealRCOT::new(rng.random(), delta);

    let mut builder = FerretConfig::builder();

    builder.param_selector(|_, _| TEST_PARAMS);

    let config = builder.build().unwrap();
    let count = TEST_PARAMS.n * 2;

    let mut sender = Sender::new(rng.random(), config.clone(), cot.clone());
    let mut receiver = Receiver::new(rng.random(), config, cot);

    assert!(sender.wants_bootstrap());
    assert!(receiver.wants_bootstrap());

    sender.alloc_bootstrap().unwrap();
    receiver.alloc_bootstrap().unwrap();

    sender.acquire_cot().flush().unwrap();
    receiver.acquire_cot().flush().unwrap();

    sender.alloc(count).unwrap();
    receiver.alloc(count).unwrap();

    while sender.wants_extend() && receiver.wants_extend() {
        sender.start_extend().unwrap();
        let msg = receiver.start_extend().unwrap();
        let msg = sender.extend(msg).unwrap();
        let msg = receiver.extend(msg).unwrap();
        let msg = sender.check(msg).unwrap();
        receiver.finish_extend(msg).unwrap();
        sender.finish_extend().unwrap();
    }

    assert!(!sender.wants_extend());
    assert!(!receiver.wants_extend());

    let RCOTSenderOutput { keys, .. } = sender.try_send_rcot(count).unwrap();
    let RCOTReceiverOutput { choices, msgs, .. } = receiver.try_recv_rcot(count).unwrap();

    assert_cot(delta, &choices, &keys, &msgs);
}
