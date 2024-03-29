/// The incremental Merkle tree used as an accumulator in the system.

use std::collections::HashMap;
use std::cmp::min;
use std::fmt::{self, Display, Formatter};

/// An error that can be encountered when reconstructing a Merkle tree.
#[derive(Debug)]
pub enum Error {
    InvalidSubtreeRoots,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match self {
			Error::InvalidSubtreeRoots => write!(f, "InvalidSubtreeRoots"),
		}
    }
}

impl std::error::Error for Error {}

/// A hash function for hashing leaves and nodes in a binary Merkle tree.
pub trait MerkleHasher {
    type Out: Default + PartialEq + Eq + Send + Sync + Clone + Copy;

    fn uncommitted(&self) -> Self::Out;
    fn hash_leaf(&self, data: &[u8]) -> Self::Out;
    fn hash_internal(&self, height: usize, left: &Self::Out, right: &Self::Out) -> Self::Out;
}

/// The incremental Merkle tree used as an accumulator in the system.
///
/// This is the same structure as is used in ZCash and the tests are ported from ZCash.
pub struct IncrementalMerkleTree<Hasher>
    where Hasher: MerkleHasher
{
    pub depth: usize,
    size: u64,

    subtree_roots: Vec<Hasher::Out>,

    // Each empty subtree root is the precomputed root of a full Merkle tree with emtpy leaves.
    // The vector contains one entry for each height up to the maximum depth.
    empty_subtree_roots: Vec<Hasher::Out>,

    tracked_leaves: HashMap<u64, Vec<Hasher::Out>>,
    hasher: Hasher,
}

impl<Hasher> IncrementalMerkleTree<Hasher>
    where Hasher: MerkleHasher
{
    pub fn new(
        depth: usize,
        size: u64,
        subtree_roots: Vec<Hasher::Out>,
        hasher: Hasher,
    ) -> Result<Self, Error>
    {
        if subtree_roots.len() != num_subtree_roots_before_index(size) {
            return Err(Error::InvalidSubtreeRoots);
        }

        let empty_subtree_roots = compute_empty_subtree_roots(depth, &hasher);
        Ok(IncrementalMerkleTree {
            depth,
            size,
            subtree_roots,
            empty_subtree_roots,
            tracked_leaves: HashMap::new(),
            hasher,
        })
    }

    pub fn empty(depth: usize, hasher: Hasher) -> Self {
        let empty_subtree_roots = compute_empty_subtree_roots(depth, &hasher);
        IncrementalMerkleTree {
            depth,
            size: 0,
            subtree_roots: Vec::new(),
            empty_subtree_roots,
            tracked_leaves: HashMap::new(),
            hasher,
        }
    }

    pub fn hasher(&self) -> &Hasher {
        &self.hasher
    }

	pub fn size(&self) -> u64 {
		self.size
	}

    pub fn root(&self) -> Hasher::Out {
        if self.is_full() {
            assert_eq!(self.subtree_roots.len(), 1);
            return self.subtree_roots[0].clone();
        }

        let index = self.size;
        let start_height = min(self.depth, index.trailing_zeros() as usize);
        let first_subtree_root = self.empty_subtree_roots[start_height];

        let mut subtree_root_iter = self.subtree_roots.iter().rev();
        (start_height..self.depth).fold(first_subtree_root, |child_hash, height| {
            let height_bit = 1u64 << (height as u64);
            let (left_child, right_child) =
                if index & height_bit == 0 {
                    let right_child = &self.empty_subtree_roots[height];
                    (&child_hash, right_child)
                } else {
                    let left_child = subtree_root_iter.next()
                        .expect("subtree roots must be non-empty");
                    (left_child, &child_hash)
                };
            self.hasher.hash_internal(height, left_child, right_child)
        })
    }

    pub fn push_data(&mut self, data: &[u8]) {
        self.push_commitment(self.hasher.hash_leaf(data))
    }

    pub fn push_commitment(&mut self, leaf: Hasher::Out) {
        assert!(!self.is_full(), "Merkle tree is at capacity");

        let index = self.size;
        self.size += 1;

        // Determine the maximum height of any branch elements for any leaves that are not the
        // root of an empty subtree.
        let max_non_empty_branch_height = subtree_height(0, self.size);

        // Determine the height of the largest fully-populated subtree that this leaf belongs in.
        let subtree_root_height = subtree_height(index, self.size);

        // Compute the new root of this fully-populated subtree.
		let mut new_nodes = Vec::with_capacity(max_non_empty_branch_height + 1);
        new_nodes.push(leaf);

        // Drop all roots that are internal to this larger subtree and replace with the new root.
        let mut subtree_root_iter = self.subtree_roots.iter().rev();
		for height in 0..max_non_empty_branch_height {
            let child_hash = &new_nodes[height];

            let height_bit = 1u64 << (height as u64);
            let (left_child, right_child) =
                if index & height_bit == 0 {
                    let right_child = &self.empty_subtree_roots[height];
                    (child_hash, right_child)
                } else {
                    let left_child = subtree_root_iter.next()
                        .expect("subtree roots must be non-empty");
                    (left_child, child_hash)
                };
            let new_node = self.hasher.hash_internal(height, left_child, right_child);
            new_nodes.push(new_node);
        }

        // Drop all roots that are internal to this larger subtree and replace with the new root.
        let subtree_roots_len = self.subtree_roots.len();
        self.subtree_roots.truncate(subtree_roots_len - subtree_root_height);
        self.subtree_roots.push(new_nodes[subtree_root_height].clone());

        // Update all tracked branches.
        for (&leaf_index, branch) in self.tracked_leaves.iter_mut() {
            assert!(leaf_index <= index);
            if leaf_index == index {
                continue;
            }

            let update_index = subtree_height(leaf_index, index);
            branch[update_index] = new_nodes[update_index];
        }
    }

    fn is_full(&self) -> bool {
        self.size >> (self.depth as u64) != 0
    }

    pub fn track_next_leaf(&mut self) {
        let index = self.size;

        let mut subtree_root_iter = self.subtree_roots.iter().rev();
        let branch = (0..self.depth)
            .map(|height| {
                let height_bit = 1u64 << (height as u64);
                if index & height_bit == 0 {
                    &self.empty_subtree_roots[height]
                } else {
                    subtree_root_iter.next().expect("subtree roots must be non-empty")
                }
            })
            .cloned()
            .collect();

        self.tracked_leaves.insert(index, branch);
    }

    pub fn state(self) -> (u64, Vec<Hasher::Out>) {
        (self.size, self.subtree_roots)
    }

    pub fn tracked_branch(&self, index: u64) -> Option<&[Hasher::Out]> {
        self.tracked_leaves.get(&index).map(|branch| branch.as_slice())
    }

    pub fn check_branch_against_root(
        &self,
        index: u64,
        leaf: &Hasher::Out,
        branch: &[Hasher::Out],
        root: &Hasher::Out
    ) -> bool
    {
        if branch.len() != self.depth {
            return false;
        }

        let computed_root = branch.iter().enumerate()
            .fold(leaf.clone(), |child_hash, (height, sibling_hash)| {
                let height_bit = 1u64 << (height as u64);
                let (left_child, right_child) =
                    if index & height_bit == 0 {
                        (&child_hash, sibling_hash)
                    } else {
                        (sibling_hash, &child_hash)
                    };
                self.hasher.hash_internal(height, left_child, right_child)
            });
        computed_root == *root
    }

    pub fn check_branch(&self, index: u64, leaf: &Hasher::Out, branch: &[Hasher::Out]) -> bool {
        self.check_branch_against_root(index, leaf, branch, &self.root())
    }
}

// Return the height of the largest subtree containing the leaf at index that contains no leaves
// with index greater than or equal to size.
fn subtree_height(index: u64, size: u64) -> usize {
    log2(index ^ size)
}

// Assuming there is a subtree root at index i-1, the number of subtree roots at indices less than i
// is given by the number of bits set in the binary representation of i.
fn num_subtree_roots_before_index(index: u64) -> usize {
    index.count_ones() as usize
}

// Precompute the roots of full Merkle trees of varying depths where all leaves are empty. Returns
// a vector a Merkle roots for the tree of each height from 0 to a maximum depth, inclusive.
fn compute_empty_subtree_roots<Hasher>(depth: usize, hasher: &Hasher) -> Vec<Hasher::Out>
    where Hasher: MerkleHasher
{
    let mut hashes = Vec::with_capacity(depth);
    hashes.push(hasher.uncommitted());
    for i in 0..depth {
        let child_hash = hashes.last().expect("hashes is not empty");
        let parent_hash = hasher.hash_internal(i, child_hash, child_hash);
        hashes.push(parent_hash);
    }
    hashes
}

// https://graphics.stanford.edu/~seander/bithacks.html#IntegerLog
fn log2(mut v: u64) -> usize {
    let b = [0x2u64, 0xCu64, 0xF0u64, 0xFF00u64, 0xFFFF0000u64, 0xFFFFFFFF00000000u64];
    let s = [1, 2, 4, 8, 16, 32];

    let mut r = 0usize;
    for i in (0..6).rev() {
        if v & b[i] != 0 {
            v >>= s[i];
            r |= s[i];
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::PedersenHasher;

	use ff::{PrimeFieldRepr, PrimeField, ScalarEngine};
    use hex::{self, FromHex};
    use pairing::bls12_381::Bls12;
    use serde_json;
    use zcash_primitives::jubjub::JubjubBls12;

    fn decode_field_element<R: PrimeFieldRepr>(data: &[u8]) -> R {
        let mut repr = R::default();
        repr.read_le(data).unwrap();
        repr
    }

    fn encode_field_element<R: PrimeFieldRepr>(repr: &R) -> Vec<u8> {
        let mut data = Vec::new();
        repr.write_le(&mut data).unwrap();
        data
    }

    fn hex_encode_field_element<R: PrimeFieldRepr>(repr: &R) -> String {
        hex::encode(encode_field_element(repr))
    }

    // Port of TEST(merkletree, EmptyrootsSapling) in zcash.
    #[test]
    fn test_empty_subtree_roots() {
        let expected_merkle_empty: Vec<String> =
            serde_json::from_str(include_str!("test_data/merkle_roots_empty_sapling.json"))
                .unwrap();

        let depth = 62;
        let jubjub_params = &JubjubBls12::new();
        let hasher = <PedersenHasher<Bls12, _>>::new(jubjub_params);

        let merkle_empty = compute_empty_subtree_roots(depth, &hasher).iter()
            .map(|hash| hex_encode_field_element(hash))
            .collect::<Vec<_>>();
        assert_eq!(merkle_empty, expected_merkle_empty);
    }

    // Port of TEST(merkletree, SaplingVectors) in zcash.
    #[test]
    fn test_merkle_root() {
        let empty_merkle_roots: Vec<String> =
            serde_json::from_str(include_str!("test_data/merkle_roots_empty_sapling.json"))
                .unwrap();
        let expected_merkle_roots: Vec<String> =
            serde_json::from_str(include_str!("test_data/merkle_roots_sapling.json"))
                .unwrap();
        let merkle_leaves_hex: Vec<String> =
            serde_json::from_str(include_str!("test_data/merkle_commitments_sapling.json"))
                .unwrap();
        let merkle_leaves: Vec<<<Bls12 as ScalarEngine>::Fr as PrimeField>::Repr> = merkle_leaves_hex.iter()
            .map(|leaf_hex| {
                let mut leaf = <[u8; 32]>::from_hex(leaf_hex).unwrap();
                leaf.as_mut().reverse();
                decode_field_element(&leaf[..])
            })
            .collect();

        let jubjub_params = &JubjubBls12::new();
        let hasher = <PedersenHasher<Bls12, _>>::new(jubjub_params);

        let mut tree = IncrementalMerkleTree::new(4, 0, Vec::new(), hasher).unwrap();

        // Empty tree root of height 4.
        assert_eq!(tree.size, 0);
        assert_eq!(hex_encode_field_element(&tree.root()), empty_merkle_roots[4]);

        for (i, (leaf, root))
            in merkle_leaves.iter().zip(expected_merkle_roots.iter()).enumerate() {

            tree.track_next_leaf();
            tree.push_commitment(leaf.clone());
            assert_eq!(tree.size, (i + 1) as u64);
            assert_eq!(hex_encode_field_element(&tree.root()), *root);
        }

        for (i, leaf) in merkle_leaves.iter().enumerate() {
            let index = i as u64;
            let branch = tree.tracked_branch(index).unwrap();
            assert!(tree.check_branch(index, leaf, branch));
        }
    }
}
