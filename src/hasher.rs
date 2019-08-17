use ff::{self, Field, PrimeField};
use zcash_primitives::{
    jubjub::JubjubEngine,
    pedersen_hash::{pedersen_hash, Personalization}
};

pub trait MerkleHasher {
    type Out: Default + PartialEq + Eq + Send + Sync + Clone + Copy;

    fn uncommitted(&self) -> Self::Out;
    fn hash_leaf(&self, data: &[u8]) -> Self::Out;
    fn hash_internal(&self, height: usize, left: &Self::Out, right: &Self::Out) -> Self::Out;
}

pub struct PedersenHasher<'a, E>
    where E: JubjubEngine
{
    pub params: &'a E::Params,
}

impl<'a, E> MerkleHasher for PedersenHasher<'a, E>
    where E: JubjubEngine
{
    type Out = <E::Fr as PrimeField>::Repr;

    // Based on librustzcash_tree_uncommitted in librustzcash.
    fn uncommitted(&self) -> Self::Out {
        E::Fr::one().into_repr()
    }

    fn hash_leaf(&self, data: &[u8]) -> Self::Out {
        let pt = pedersen_hash::<E, _>(
            Personalization::NoteCommitment,
            BitIterator::new(data),
            &self.params
        );
        pt.into_xy().0.into_repr()
    }

    // Compute the hash of an internal node in the Merkle tree given the child hashes.
    // See PedersenHash::combine in zcash.
    fn hash_internal(&self, height: usize, left: &Self::Out, right: &Self::Out) -> Self::Out {
        let mut lhs = [false; 256];
        let mut rhs = [false; 256];

        for (a, b) in lhs.iter_mut().rev().zip(ff::BitIterator::new(left)) {
            *a = b;
        }

        for (a, b) in rhs.iter_mut().rev().zip(ff::BitIterator::new(right)) {
            *a = b;
        }

        let num_bits = E::Fr::NUM_BITS as usize;
        let left_bits = lhs.iter().map(|&x| x).take(num_bits);
        let right_bits = rhs.iter().map(|&x| x).take(num_bits);

        let pt = pedersen_hash::<E, _>(
            Personalization::MerkleTree(height),
            left_bits.chain(right_bits),
            &self.params
        );
        pt.into_xy().0.into_repr()
    }
}

impl<'a, E> PedersenHasher<'a, E>
    where E: JubjubEngine
{
    pub fn new(params: &'a E::Params) -> Self {
        PedersenHasher { params }
    }

//    fn point_to_hash(&self, pt: &edwards::Point<E, PrimeOrder>) -> <Self as MerkleHasher>::Out {
//        self.field_element_to_hash(pt.into_xy().0)
//    }
//
//    fn field_element_to_hash(&self, x: E::Fr) -> <Self as MerkleHasher>::Out {
//        let mut result = H256::default();
//        x.into_repr().write_le(result.as_mut())
//            .expect("the field element representation is 32 bytes");
//        result
//    }
//
//    fn field_element_read_le(&self, hash: &<Self as MerkleHasher>::Out)
//        -> <E::Fr as PrimeField>::Repr
//    {
//        let mut repr = <E::Fr as PrimeField>::Repr::default();
//        repr.read_le(hash.as_ref())
//            .expect("the field element representation is 32 bytes");
//        repr
//    }
}

struct BitIterator<'a> {
    data: &'a [u8],
    index: usize,
}

impl<'a> BitIterator<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitIterator {
            data,
            index: 0,
        }
    }
}

impl<'a> Iterator for BitIterator<'a> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        let byte_index = self.index / 8;
        let bit_index = self.index % 8;

        self.index += 1;

        if byte_index < self.data.len() {
            Some((self.data[byte_index] & (1 << bit_index)) != 0)
        } else {
            None
        }
    }
}
