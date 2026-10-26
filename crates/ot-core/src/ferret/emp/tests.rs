use super::wire;
use crate::{
    ferret::{FerretConfig, Receiver, Sender, config::TEST_PARAMS},
    ideal::{emp_rcot::EmpRCOT, rcot::IdealRCOT},
    rcot::{RCOTReceiver, RCOTSender},
};
use mpz_core::Block;
use rand::{SeedableRng, rngs::StdRng};

const GOLDEN: &str = include_str!("../../../tests/data/ferret_b11_round.txt");

/// Returns the value after the `name ` tag in the golden fixture.
fn golden_line(name: &str) -> &'static str {
    GOLDEN
        .lines()
        .find_map(|l| {
            let (tag, rest) = l.split_once(' ')?;
            (tag == name).then_some(rest)
        })
        .unwrap_or_else(|| panic!("golden is missing `{name}`"))
}

/// Decodes a hex field of the golden fixture.
fn golden_hex(name: &str) -> Vec<u8> {
    let s = golden_line(name);
    assert!(s.len() % 2 == 0, "odd hex length for `{name}`");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// Decodes a 16-byte block field of the golden fixture.
fn golden_block(name: &str) -> Block {
    Block::from(<[u8; 16]>::try_from(golden_hex(name)).unwrap())
}

/// One extension round, with the extend messages run through the emp-ot wire
/// adapters. Checks their shapes.
#[test]
fn test_emp_wire_shapes() {
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

    sender.alloc_bootstrap().unwrap();
    receiver.alloc_bootstrap().unwrap();
    sender.acquire_cot().flush().unwrap();
    receiver.acquire_cot().flush().unwrap();
    sender.alloc(count).unwrap();
    receiver.alloc(count).unwrap();

    sender.start_extend().unwrap();
    let receiver_extend = receiver.start_extend().unwrap();
    let recv_ext = wire::receiver_extend(&receiver_extend);
    let sender_extend = sender.extend(receiver_extend).unwrap();
    let send = wire::sender_extend(&sender_extend);

    let tree_depth = (TEST_PARAMS.n / TEST_PARAMS.t).ilog2() as usize;
    // emp's sender→receiver stream: one `tree_depth`-block `c` per tree.
    assert_eq!(send.len(), TEST_PARAMS.t as usize * tree_depth * 16);
    // emp sends nothing on the extend from the receiver.
    assert_eq!(recv_ext.len(), 0);
}

/// One extension round, byte-for-byte against emp-ot.
///
/// The fixture is `tests/data/ferret_b11_round.txt`, captured from
/// `tools/dump_ferret_golden.cpp` (`ferret_b11`: t=1170, tree_depth=11,
/// non-malicious, sid=0) under `EMP_TEST_MODE=1`. The sender's PRG is seeded
/// with emp-tool's own test-mode gadget-PRG seed, so no reseed hook is needed
/// on the emp side.
#[cfg(feature = "emp")]
#[test]
fn test_emp_round_c() {
    let params = mpz_core::lpn::LpnParameters {
        n: golden_line("n").parse().unwrap(),
        k: golden_line("k").parse().unwrap(),
        t: golden_line("t").parse().unwrap(),
    };
    let tree_depth: usize = golden_line("tree_depth").parse().unwrap();

    let seed = golden_block("seed");
    let delta = golden_block("delta");
    let gadget_seed = golden_block("gadget_seed");

    let mut builder = FerretConfig::builder();
    builder.param_selector(move |_, _| params);
    let config = builder.build().unwrap();

    let cot = EmpRCOT::new(seed, delta);
    let mut sender = Sender::new(gadget_seed, config.clone(), cot.clone());
    let mut receiver = Receiver::new(gadget_seed, config, cot);

    // A single alloc allocates on both roles (EmpRCOT::alloc does both), so
    // the first round consumes the base correlations from offset 0.
    sender.alloc_bootstrap().unwrap();
    sender.acquire_cot().flush();

    sender.alloc(params.n).unwrap();
    receiver.alloc(params.n).unwrap();

    sender.start_extend().unwrap();
    let re = receiver.start_extend().unwrap();
    let se = sender.extend(re).unwrap();
    let wire = wire::sender_extend(&se);

    let want = golden_hex("first_tree");
    assert!(
        wire.len() >= want.len(),
        "wire too short: {} < {}",
        wire.len(),
        want.len()
    );
    assert_eq!(
        &wire[..tree_depth * 16],
        &want[..],
        "first tree c diverges from emp"
    );

    // Whole round: emp's trace is its b11 round's 1170 tree-sends
    // (t trees), = t * tree_depth * 16 bytes.
    assert_eq!(wire.len(), params.t as usize * tree_depth * 16);
    use sha2::Digest;
    let got = sha2::Sha256::digest(&wire);
    assert_eq!(
        got.as_slice(),
        golden_hex("round_sha256").as_slice(),
        "round c stream diverges from emp"
    );
}
