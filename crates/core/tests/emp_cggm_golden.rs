//! Byte-for-byte cGGM golden test against emp-ot.
//!
//! The fixture in `data/cggm_golden.txt` is produced by
//! `tools/emp-goldens/dump_cggm_golden.cpp`, which documents its format and the
//! fixed `(delta, seed, rev)` it uses.
//!
//! With the `emp` feature `mpz_core::cggm` masks the leaf low bit and hashes
//! under emp-ot's all-zero `CCRH` key, so its output must match exactly.
#![cfg(feature = "emp")]

use mpz_core::cggm;

const GOLDEN: &str = include_str!("data/cggm_golden.txt");

/// Returns the value after the `name ` tag.
fn line(name: &str) -> &'static str {
    GOLDEN
        .lines()
        .find_map(|l| {
            let (tag, rest) = l.split_once(' ')?;
            (tag == name).then_some(rest)
        })
        .unwrap_or_else(|| panic!("golden is missing `{name}`"))
}

fn hex(name: &str) -> Vec<u8> {
    let s = line(name);
    assert!(s.len().is_multiple_of(2), "odd hex length for `{name}`");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn block(name: &str) -> [u8; 16] {
    hex(name)
        .try_into()
        .unwrap_or_else(|_| panic!("`{name}` is not 16 bytes"))
}

fn blocks(name: &str) -> Vec<[u8; 16]> {
    hex(name).as_chunks::<16>().0.to_vec()
}

#[test]
fn emp_cggm_golden() {
    let depth: usize = line("depth").parse().unwrap();
    let rev: usize = line("rev").parse().unwrap();
    let n = 1usize << depth;

    let delta = block("delta");
    let seed = block("seed");
    let want_sender = blocks("sender");
    let want_k0 = blocks("k0");
    let krecv = blocks("krecv");
    let want_recv = blocks("recv");
    assert_eq!(want_sender.len(), n);
    assert_eq!(want_k0.len(), depth);
    assert_eq!(krecv.len(), depth);
    assert_eq!(want_recv.len(), n);

    // Sender: build the tree and compare the leaves and the shipped sums.
    let mut leaves = vec![[0u8; 16]; n];
    let mut sums = vec![[0u8; 16]; depth];
    cggm::expand(delta, seed, &mut leaves, &mut sums);
    assert_eq!(
        leaves, want_sender,
        "cGGM sender leaves diverge from emp-ot"
    );
    assert_eq!(sums, want_k0, "cGGM sender K0 diverges from emp-ot");

    // Receiver: reconstruct from the off-path corrections.
    let mut recv = vec![[0u8; 16]; n];
    cggm::expand_punctured(rev, &krecv, &mut recv);
    assert_eq!(recv, want_recv, "cGGM receiver leaves diverge from emp-ot");
}
