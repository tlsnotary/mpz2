//! GGM tree.

use std::{cmp::Ordering, ops::Range};

use itybity::ToBits;

use crate::{Block, tkprp::TwoKeyPrp};

/// Returns the range of nodes at the given layer.
#[inline]
fn layer(n: usize) -> Range<usize> {
    let start = (1 << n) - 1;
    let end = start + (1 << n);

    start..end
}

/// Returns the width of the tree at the given depth.
#[inline]
fn width(n: usize) -> usize {
    1 << n
}

/// GGM tree.
pub struct GgmTree<'a> {
    depth: usize,
    buf: Vec<Block>,
    leaves: &'a mut [Block],
}

impl<'a> GgmTree<'a> {
    /// Creates a new GGM tree.
    ///
    /// # Arguments
    ///
    /// * `depth` - The depth of the tree.
    /// * `seed` - The seed of the tree.
    /// * `leaves` - The leaves of the tree.
    pub fn new_from_seed(depth: usize, seed: Block, leaves: &'a mut [Block]) -> Self {
        assert_eq!(leaves.len(), 1 << depth, "invalid length of leaves");

        let mut buf = vec![Block::ZERO; (1 << depth) - 1];

        let tkprp = TwoKeyPrp::new([Block::ZERO, Block::ONE]);

        buf[0] = seed;
        for n in 0..depth - 1 {
            let parents = layer(n);
            let children = layer(n + 1);

            let (parents, children) = buf[parents.start..children.end].split_at_mut(width(n));

            tkprp.expand(parents, children);
        }

        // Expand the last layer.
        tkprp.expand(&buf[layer(depth - 1)], leaves);

        Self { depth, buf, leaves }
    }

    /// Recovers a partial GGM tree which is missing a leaf at the given
    /// index. Missing nodes in the tree are set to zero.
    ///
    /// See page 14 of https://eprint.iacr.org/2020/925 for a more detailed explanation.
    ///
    /// # Panics
    ///
    /// - If the position is out of bounds.
    /// - If the length of the sums is not equal to the depth minus one.
    ///
    /// # Arguments
    ///
    /// * `depth` - Depth of the tree.
    /// * `sums` - Sum of either the left or the right sibling nodes for each
    ///   layer.
    /// * `idx` - Index of the missing leaf.
    /// * `leaves` - Leaves of the tree.
    pub fn new_partial(depth: usize, sums: &[Block], idx: usize, leaves: &'a mut [Block]) -> Self {
        assert_eq!(leaves.len(), 1 << depth, "invalid length of leaves");
        assert!(idx < leaves.len(), "index out of bounds");
        assert_eq!(sums.len(), depth, "invalid length of sums");

        let mut buf = vec![Block::ZERO; (1 << depth) - 1];

        let tkprp = TwoKeyPrp::new([Block::ZERO, Block::ONE]);

        // The path length is equal to the depth of the tree.
        let idx = idx as u32;
        let path = idx.iter_msb0().skip(32 - depth);

        // Recovers the value of the sibling node.
        fn recover(layer: &mut [Block], sum: Block, offset: usize, select: bool) {
            layer[offset + select as usize] = Block::ZERO;
            layer[offset + !select as usize] = Block::ZERO;

            // If `select` is a left node, we fold all the right nodes and vice
            // versa.
            let value = layer
                .iter()
                .skip(!select as usize)
                .step_by(2)
                .fold(sum, |acc, value| acc ^ value);

            // Set the value of the sibling.
            layer[offset + !select as usize] = value;
        }

        // An offset in a layer of either the node in the path or its sibling.
        let mut offset = 0;
        for ((select, sum), n) in path.zip(sums).zip(1..depth + 1) {
            if n < depth - 1 {
                let (inputs, outputs) =
                    buf[layer(n).start..layer(n + 1).end].split_at_mut(width(n));

                recover(inputs, *sum, offset, select);

                tkprp.expand(inputs, outputs);
            } else if n == depth - 1 {
                let inputs = &mut buf[layer(n)];

                recover(inputs, *sum, offset, select);

                tkprp.expand(inputs, leaves);
            } else if n == depth {
                recover(leaves, *sum, offset, select);

                break;
            }

            offset += select as usize;
            offset <<= 1;
        }

        Self { depth, buf, leaves }
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> &Block {
        &self.buf[0]
    }

    /// Returns the depth of the tree.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Returns the layer at the given depth.
    pub fn layer(&self, depth: usize) -> Option<&[Block]> {
        match depth.cmp(&self.depth) {
            Ordering::Less => Some(&self.buf[layer(depth)]),
            Ordering::Equal => Some(self.leaves),
            Ordering::Greater => None,
        }
    }

    /// Returns an iterator over the layers of the GGM tree.
    pub fn iter_layers(&self) -> impl Iterator<Item = &[Block]> {
        (0..=self.depth).flat_map(|i| self.layer(i))
    }

    /// Returns the sums of the left and right nodes for each layer.
    pub fn layer_sums(&self) -> impl Iterator<Item = [Block; 2]> + '_ {
        self.iter_layers().skip(1).map(|layer| {
            let mut left = Block::ZERO;
            let mut right = Block::ZERO;

            for nodes in layer.as_chunks::<2>().0 {
                left ^= nodes[0];
                right ^= nodes[1];
            }

            [left, right]
        })
    }

    /// Returns the leaves of the GGM tree.
    pub fn leaves(&self) -> &[Block] {
        self.leaves
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ggm() {
        let seed = Block::ONES;
        let depth = 4;

        let mut leaves = vec![Block::ZERO; 1 << depth];

        GgmTree::new_from_seed(depth, seed, &mut leaves);

        assert!(leaves.iter().all(|leaf| *leaf != Block::ZERO));
    }

    #[test]
    fn test_ggm_get_layer() {
        let seed = Block::ONES;
        let depth = 4;

        let mut leaves = vec![Block::ZERO; 1 << depth];

        let ggm = GgmTree::new_from_seed(depth, seed, &mut leaves);

        for i in 0..depth {
            let layer = ggm.layer(i).unwrap();

            assert_eq!(layer.len(), 1 << i);
        }
    }

    #[test]
    fn test_ggm_partial() {
        let seed = Block::ONES;
        let depth = 4;

        let mut full_leaves = vec![Block::ZERO; 1 << depth];
        let ggm = GgmTree::new_from_seed(depth, seed, &mut full_leaves);

        for i in 0..1 << depth {
            let path = i as u32;
            let sums = ggm
                .layer_sums()
                .zip(path.iter_msb0().skip(32 - depth))
                .map(|(sum, select)| sum[!select as usize])
                .collect::<Vec<_>>();

            let mut leaves = vec![Block::ZERO; 1 << depth];
            let ggm_partial = GgmTree::new_partial(depth, &sums, i, &mut leaves);
            let mut full_leaves = ggm.leaves().to_vec();

            full_leaves[i] = Block::ZERO;

            assert_eq!(ggm_partial.leaves(), full_leaves.as_slice());
        }
    }
}
