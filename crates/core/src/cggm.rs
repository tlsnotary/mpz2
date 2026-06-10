//! Correlated GGM tree, also known as the "half-tree".
//!
//! Implements the cGGM construction from [Half-Tree](https://eprint.iacr.org/2022/1431)
//! (Figure 3). Every parent node `x` has left child `H(x)` and right child
//! `x ⊕ H(x)`, where `H` is a circular correlation-robust hash function. This
//! maintains the invariant that the nodes of every level XOR to the global
//! offset `delta`, which halves both the computation (1 hash per node pair)
//! and the communication (1 block per level) of a distributed point function
//! compared to a standard GGM tree.
//!
//! # Layout
//!
//! Each level is expanded in place using the split layout: the left children
//! overwrite their parents in the lower half of the buffer and the right
//! children are appended to the upper half. Consequently, the leaf reached by
//! taking the `b_i` child at level `i` is stored at index `Σ b_i ⋅ 2^(i-1)`,
//! i.e. an index encodes its path with the level-1 bit in the least
//! significant position.

use crate::aes::FIXED_KEY_AES;

/// A zero node.
const ZERO: [u8; 16] = [0; 16];

/// XOR of two 16-byte blocks.
#[inline(always)]
fn xor(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    (u128::from_ne_bytes(a) ^ u128::from_ne_bytes(b)).to_ne_bytes()
}

/// Number of nodes hashed per batch in [`expand_level`]. Large enough to
/// saturate the AES backend, small enough to keep the scratch buffer on the
/// stack.
const BATCH: usize = 64;

/// Expands one level in place using the split layout.
///
/// `nodes[..n]` holds the parents. Writes the left children to `nodes[..n]`
/// and the right children to `nodes[n..2n]`, returning the XOR sum of the
/// children on one side, selected by `right`.
fn expand_level(nodes: &mut [[u8; 16]], n: usize, right: bool) -> [u8; 16] {
    let (left, rest) = nodes.split_at_mut(n);
    let right_half = &mut rest[..n];

    // left = H(parent), right = parent ⊕ H(parent), in a single pass over
    // the parents with the hashes batched through a stack buffer.
    let mut sum = ZERO;
    let mut h = [ZERO; BATCH];
    for (left, right_half) in left.chunks_mut(BATCH).zip(right_half.chunks_mut(BATCH)) {
        let h = &mut h[..left.len()];
        FIXED_KEY_AES.ccr_blocks_to(left, h);

        for ((l, r), h) in left.iter_mut().zip(right_half.iter_mut()).zip(&*h) {
            *r = xor(*l, *h);
            *l = *h;
            sum = xor(sum, if right { *r } else { *l });
        }
    }

    sum
}

/// Expands a cGGM tree.
///
/// The two level-1 nodes are `(seed, delta ⊕ seed)`, so the nodes of every
/// level XOR to `delta`. Writes the left-node sum of level `i` to
/// `sums[i - 1]`; the corresponding right-node sum is `delta ⊕ sums[i - 1]`.
///
/// # Panics
///
/// - If `sums` is empty.
/// - If the length of `leaves` is not `2^depth`, where `depth = sums.len()`.
///
/// # Arguments
///
/// * `delta` - The global offset of the tree.
/// * `seed` - The left level-1 node.
/// * `leaves` - The leaves of the tree.
/// * `sums` - Sum of the left nodes for each level.
pub fn expand(delta: [u8; 16], seed: [u8; 16], leaves: &mut [[u8; 16]], sums: &mut [[u8; 16]]) {
    let depth = sums.len();
    assert!(depth >= 1, "depth must be at least 1");
    assert_eq!(leaves.len(), 1 << depth, "invalid length of leaves");

    leaves[0] = seed;
    leaves[1] = xor(delta, seed);
    sums[0] = seed;

    for i in 2..=depth {
        let n = 1 << (i - 1);
        sums[i - 1] = expand_level(&mut leaves[..2 * n], n, false);
    }
}

/// Expands a partial cGGM tree which is missing the leaf at the given index.
///
/// The missing leaf is set to zero. The path bit of level `i` is bit `i - 1`
/// of `idx`, and `sums[i - 1]` must be the sum of the nodes on the *opposite*
/// side of the path at level `i`: `sums[i - 1] = !path_bit ⋅ delta ⊕ left_sum`,
/// where `left_sum` is the corresponding output of [`expand`].
///
/// # Panics
///
/// - If `sums` is empty.
/// - If the length of `leaves` is not `2^depth`, where `depth = sums.len()`.
/// - If `idx` is out of bounds.
///
/// # Arguments
///
/// * `idx` - Index of the missing leaf.
/// * `sums` - Sum of the off-path sibling nodes for each level.
/// * `leaves` - The leaves of the tree.
pub fn expand_punctured(idx: usize, sums: &[[u8; 16]], leaves: &mut [[u8; 16]]) {
    let depth = sums.len();
    assert!(depth >= 1, "depth must be at least 1");
    assert_eq!(leaves.len(), 1 << depth, "invalid length of leaves");
    assert!(idx < leaves.len(), "index out of bounds");

    // Level 1: only the off-path node is known. The on-path node is set to
    // zero, which the levels below rely on; every other slot is overwritten
    // before it is read.
    let b = idx & 1;
    leaves[b] = ZERO;
    leaves[b ^ 1] = sums[0];

    // Index of the on-path node within the current level.
    let mut pos = b;
    for i in 2..=depth {
        let half = 1 << (i - 1);
        let b = (idx >> (i - 1)) & 1;

        // Expand the entire level, summing the nodes on the off-path side.
        let sum = expand_level(&mut leaves[..2 * half], half, b == 0);

        // The on-path parent is zero, so both of its children hold the junk
        // value H(0): the left child at `pos` and the right child at
        // `pos + half`. Remove the junk from the off-path side sum to recover
        // the sibling of the on-path node.
        let junk = leaves[pos];
        leaves[pos] = ZERO;
        leaves[pos + half] = ZERO;
        leaves[pos + (b ^ 1) * half] = xor(xor(sum, junk), sums[i - 1]);

        pos += b * half;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{Rng, SeedableRng, rngs::StdRng};

    #[test]
    fn test_cggm_level_correlation() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta: [u8; 16] = rng.random();
        let seed: [u8; 16] = rng.random();
        let depth = 4;

        let mut leaves = vec![ZERO; 1 << depth];
        let mut sums = vec![ZERO; depth];

        expand(delta, seed, &mut leaves, &mut sums);

        // The nodes of every level XOR to delta, in particular the leaves.
        let sum = leaves.iter().fold(ZERO, |acc, leaf| xor(acc, *leaf));
        assert_eq!(sum, delta);
    }

    #[test]
    fn test_cggm_punctured() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta: [u8; 16] = rng.random();

        for depth in 1..=4 {
            let seed: [u8; 16] = rng.random();

            let mut leaves = vec![ZERO; 1 << depth];
            let mut sums = vec![ZERO; depth];
            expand(delta, seed, &mut leaves, &mut sums);

            for idx in 0..1 << depth {
                // The off-path sum at level i is the left sum if the path
                // goes right, and the right sum (left sum ⊕ delta) otherwise.
                let punctured_sums: Vec<[u8; 16]> = sums
                    .iter()
                    .enumerate()
                    .map(|(i, &sum)| {
                        if (idx >> i) & 1 == 1 {
                            sum
                        } else {
                            xor(sum, delta)
                        }
                    })
                    .collect();

                // Pre-fill with garbage: the expansion must not rely on a
                // zeroed buffer.
                let mut punctured = vec![[0xffu8; 16]; 1 << depth];
                expand_punctured(idx, &punctured_sums, &mut punctured);

                let mut expected = leaves.clone();
                expected[idx] = ZERO;
                assert_eq!(punctured, expected);

                // The punctured leaf is recovered offset by delta.
                let fold = punctured.iter().fold(ZERO, |acc, w| xor(acc, *w));
                assert_eq!(fold, xor(leaves[idx], delta));
            }
        }
    }
}
