//! Byte-for-byte golden test against emp-ot.
//!
//! The fixture in `data/lpn_golden.txt` is produced by
//! `tools/emp-goldens/dump_lpn_golden.cpp`, which documents its format and how
//! `x` and `e` are regenerated.
//!
//! With the `emp` feature the Rust `LpnEncoder` derives its matrix from
//! the same monotone PRG counter stream emp-ot uses, so the result hash must
//! match.
#![cfg(feature = "emp")]

use mpz_core::{lpn::LpnEncoder, prg::Prg, Block};
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

const GOLDEN: &str = include_str!("data/lpn_golden.txt");

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
    assert!(s.len() % 2 == 0, "odd hex length for `{name}`");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn blocks(bytes: &[u8]) -> Vec<[u8; 16]> {
    bytes.chunks_exact(16).map(|c| c.try_into().unwrap()).collect()
}

#[test]
fn emp_lpn_golden() {
    let k_log: u32 = line("k_log").parse().unwrap();
    let n: usize = line("n").parse().unwrap();
    let k: usize = 1 << k_log;
    // Exact emp-ot equivalence only holds for lengths that are a multiple of 4.
    assert_eq!(n % 4, 0, "golden length must be a multiple of 4");

    let seed: [u8; 16] = hex("seed").try_into().unwrap();
    let fill_seed: [u8; 16] = hex("fill_seed").try_into().unwrap();
    let want: [u8; 32] = hex("sha256_y").try_into().unwrap();

    // Regenerate x (k blocks) then e (n blocks) from the fill PRG.
    let mut prg = Prg::from_seed(Block::from(fill_seed));
    let mut x_bytes = vec![0u8; k * 16];
    prg.fill_bytes(&mut x_bytes);
    let mut y_bytes = vec![0u8; n * 16];
    prg.fill_bytes(&mut y_bytes); // `y` starts as the error vector `e`

    let x = blocks(&x_bytes);
    let mut y = blocks(&y_bytes);
    LpnEncoder::<10>::new(k as u32).compute(seed, &mut y, &x);

    let mut flat = Vec::with_capacity(n * 16);
    for b in &y {
        flat.extend_from_slice(b);
    }
    let got: [u8; 32] = Sha256::digest(&flat).into();
    assert_eq!(got, want, "emp result hash diverges from emp-ot");
}
