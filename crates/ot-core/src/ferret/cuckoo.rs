//! Implementation of Cuckoo hash.

use std::array::from_fn;

use mpz_core::{Block, aes::AesEncryptor};

pub(crate) const HASH_NUM: u32 = 3;
const TRIAL_NUM: usize = 100;

/// Bucket index in the table.
type BucketIdx = usize;
/// Position of item in the bucket.
type BucketPos = usize;

/// Cuckoo hash insertion error
#[derive(Debug, thiserror::Error)]
#[error("cycle detected in Cuckoo hashing")]
pub(crate) struct CuckooHashError;

/// Item in Cuckoo hash table.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct Item {
    /// Value in the table.
    pub(crate) value: u32,
    /// Which hash function is used.
    pub(crate) hash_idx: u32,
}

/// Implementation of Cuckoo hash. See [here](https://eprint.iacr.org/2019/1084.pdf) for reference.
pub(crate) struct CuckooHash {
    table: Vec<Option<Item>>,
}

impl CuckooHash {
    /// Creates a Cuckoo hash table from the provided hashes and items.
    pub(crate) fn new(
        hashes: &[AesEncryptor; HASH_NUM as usize],
        items: &[usize],
    ) -> Result<Self, CuckooHashError> {
        // Always sets m = 1.5 * t. t is the length of `items`.
        let m = compute_table_length(items.len());

        // Allocates table.
        let mut table = vec![None; m];
        // Inserts each item.
        for &value in items {
            Self::hash(hashes, &mut table, value as u32)?;
        }

        Ok(Self { table })
    }

    /// Returns an iterator over the table.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Option<Item>> {
        self.table.iter()
    }

    // Hash an element to a position with the current hash function.
    #[inline]
    fn hash(
        hashes: &[AesEncryptor; HASH_NUM as usize],
        table: &mut [Option<Item>],
        value: u32,
    ) -> Result<(), CuckooHashError> {
        // The item consists of the value and hash index, starting from 0.
        let mut item = Item { value, hash_idx: 0 };

        for _ in 0..TRIAL_NUM {
            // Computes the position of the value.
            let pos = hash_to_index(&hashes[item.hash_idx as usize], table.len(), item.value);

            // Inserts the value to position `pos`.
            let opt_item = table[pos].replace(item);

            // If position `pos` is not empty before the above insertion,
            // iteratively inserts the obtained value.
            if let Some(x) = opt_item {
                item = x;
                item.hash_idx = (item.hash_idx + 1) % HASH_NUM;
            } else {
                // If no value assigned to position `pos`, end the process.
                return Ok(());
            }
        }
        Err(CuckooHashError)
    }
}

/// Implementation of Bucket. See step 3 in Figure 7.
#[derive(Debug)]
pub(crate) struct Buckets {
    buckets: Vec<usize>,
    /// Maps an index to the buckets it is in and the corresponding position in
    /// each bucket.
    items: Vec<[(BucketIdx, BucketPos); HASH_NUM as usize]>,
}

impl Buckets {
    /// Creates new buckets.
    ///
    /// # Arguments
    ///
    /// * `hashes` - Cuckoo hash functions.
    /// * `count` - Number of indices that will be queried.
    /// * `domain` - Domain of the indices, ie [0, len).
    pub(crate) fn new(
        hashes: &[AesEncryptor; HASH_NUM as usize],
        count: usize,
        domain: usize,
    ) -> Self {
        let m = compute_table_length(count);

        // NOTE: the sorted step in Step 3.c can be removed.

        let mut buckets = vec![0; m];
        let mut items = Vec::with_capacity(domain);
        for value in 0..domain as u32 {
            items.push(from_fn(|hash_idx| {
                let hash = &hashes[hash_idx];
                let bucket_idx = hash_to_index(hash, m, value);
                let pos = buckets[bucket_idx];
                buckets[bucket_idx] += 1;
                (bucket_idx, pos)
            }));
        }

        Self { buckets, items }
    }

    /// Returns the buckets and positions for the given index.
    pub(crate) fn get(&self, idx: usize) -> &[(usize, usize); HASH_NUM as usize] {
        &self.items[idx]
    }

    /// Returns an iterator over the bucket lengths.
    pub(crate) fn iter_buckets(&self) -> impl Iterator<Item = usize> + '_ {
        self.buckets.iter().copied()
    }

    /// Returns an iterator over the bucket indices and item positions.
    #[inline]
    pub(crate) fn iter_items(
        &self,
    ) -> impl Iterator<Item = &[(usize, usize); HASH_NUM as usize]> + '_ {
        self.items.iter()
    }
}

// Always sets m = 1.5 * t. t is the length of `alphas`. See Section 7.1
// Parameter Selection.
#[inline(always)]
fn compute_table_length(t: usize) -> usize {
    (1.5 * (t as f32)).ceil() as usize
}

// Hash the value into index using AES.
#[inline(always)]
fn hash_to_index(hash: &AesEncryptor, range: usize, value: u32) -> usize {
    let mut blk: Block = bytemuck::cast::<_, Block>(value as u128);
    blk = hash.encrypt_block(blk);
    let res = u128::from_le_bytes(blk.to_bytes());
    (res as usize) % range
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_core::aes::AesEncryptor;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    #[test]
    fn test_cuckoo_buckets() {
        let mut rng = StdRng::seed_from_u64(0);
        const NUM: usize = 50;

        let hashes = from_fn(|_| AesEncryptor::new(rng.random()));

        let input: [usize; NUM] = std::array::from_fn(|i| i);
        let cuckoo = CuckooHash::new(&hashes, &input).unwrap();
        let buckets = Buckets::new(&hashes, NUM, 2 * NUM);

        for (bucket_idx, item) in cuckoo.table.iter().enumerate() {
            if let Some(item) = item {
                // Assert this item is in the corresponding bucket.
                assert_eq!(
                    bucket_idx,
                    buckets.items[item.value as usize][item.hash_idx as usize].0
                );
            }
        }
    }
}
