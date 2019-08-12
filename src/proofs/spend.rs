use crate::constants;
use crate::transaction::{Nullifier, Value};

use ff::Field;
use bellman::{self, SynthesisError, ConstraintSystem};
use sapling_crypto::{
	circuit::{blake2s, boolean, ecc, num, pedersen_hash, multipack},
	jubjub::{edwards, FixedGenerators, JubjubEngine, Unknown},
};
use std::iter;

pub struct Assignment<E>
	where E: JubjubEngine
{
	pub position: u64,
	pub value: Value,
	pub value_nonce_old: E::Fs,
	pub value_nonce_new: E::Fs,

	pub privkey: E::Fs,
	pub pubkey_base_old: edwards::Point<E, Unknown>,
	pub pubkey_base_new: edwards::Point<E, Unknown>,

	pub nullifier: Nullifier,

	/// The authentication path of the commitment in the tree
	pub auth_path: Vec<E::Fr>,

	/// The anchor; the root of the tree. If the note being
	/// spent is zero-value, this can be anything.
	pub anchor: E::Fr,
}

pub struct Circuit<'a, E>
	where E: JubjubEngine,
{
	pub params: &'a E::Params,
	pub merkle_depth: usize,
	pub assigned: Option<Assignment<E>>,
}

impl<'a, E> Circuit<'a, E>
	where E: JubjubEngine,
{
	pub fn without_assignment(params: &'a E::Params, merkle_depth: usize) -> Self {
		Circuit {
			params,
			merkle_depth,
			assigned: None,
		}
	}
}

fn num_from_bits_le<E, CS>(value_bits: &[boolean::Boolean]) -> num::Num<E>
	where
		E: JubjubEngine,
		CS: ConstraintSystem<E>,
{
	let mut coeff = E::Fr::one();
	value_bits.iter().fold(num::Num::zero(), |value_num, bit| {
		let value_num = value_num.add_bool_with_coeff(
			CS::one(),
			bit,
			coeff
		);
		coeff.double();
		value_num
	})
}

impl<'a, E> Circuit<'a, E>
	where E: JubjubEngine,
{
	fn get_assigned<T>(&self, f: impl FnOnce(&Assignment<E>) -> T) -> Option<T> {
		self.assigned.as_ref().map(f)
	}
}

impl<'a, E> bellman::Circuit<E> for Circuit<'a, E>
	where E: JubjubEngine,
{
	fn synthesize<CS>(self, cs: &mut CS) -> Result<(), SynthesisError>
		where CS: ConstraintSystem<E>
	{
		// Booleanize the value into little-endian bit order.
		let value_bits = boolean::u64_into_boolean_vec_le(
			cs.namespace(|| "value bits"),
			self.get_assigned(|assigned| assigned.value)
		)?;

		// Construct the value as a field element from bits.
		let value_num = num_from_bits_le::<E, CS>(&value_bits);

		// Compute the note value in the exponent.
		let value_pt = ecc::fixed_base_multiplication(
			cs.namespace(|| "compute the value in the exponent"),
			FixedGenerators::ValueCommitmentValue,
			&value_bits,
			self.params
		)?;

		// Booleanize the old nonce. This does not ensure the bit representation is "in the field"
		// because it doesn't matter for security.
		let value_nonce_old_bits = boolean::field_into_boolean_vec_le(
			cs.namespace(|| "old value nonce"),
			self.assigned.as_ref().map(|assigned| assigned.value_nonce_old.clone())
		)?;

		// Compute the randomness in the exponent.
		let value_nonce_old_pt = ecc::fixed_base_multiplication(
			cs.namespace(|| "compute the old value nonce in the exponent"),
			FixedGenerators::ValueCommitmentRandomness,
			&value_nonce_old_bits,
			self.params
		)?;

		// Compute the old Pedersen commitment to the value.
		let value_comm_old = value_pt.add(
			cs.namespace(|| "old value commitment"),
			&value_nonce_old_pt,
			self.params
		)?;

		// Booleanize the old nonce. This does not ensure the bit representation is "in the field"
		// because it doesn't matter for security.
		let value_nonce_new_bits = boolean::field_into_boolean_vec_le(
			cs.namespace(|| "new value nonce"),
			self.get_assigned(|assigned| assigned.value_nonce_new.clone())
		)?;

		// Compute the randomness in the exponent.
		let value_nonce_new_pt = ecc::fixed_base_multiplication(
			cs.namespace(|| "compute the new value nonce in the exponent"),
			FixedGenerators::ValueCommitmentRandomness,
			&value_nonce_new_bits,
			self.params
		)?;

		// Compute the new Pedersen commitment to the value.
		let value_comm_new = value_pt.add(
			cs.namespace(|| "new value commitment"),
			&value_nonce_new_pt,
			self.params
		)?;

		// Booleanize the representation of the old value commitment.
		let value_comm_old_bits = value_comm_old.repr(
			cs.namespace(|| "old value commitment bits")
		)?;

		let pubkey_base_old = ecc::EdwardsPoint::witness(
			cs.namespace(|| "old pubkey base point"),
			self.get_assigned(|assigned| assigned.pubkey_base_old.clone()),
			self.params
		)?;
		let pubkey_base_new = ecc::EdwardsPoint::witness(
			cs.namespace(|| "new pubkey base point"),
			self.get_assigned(|assigned| assigned.pubkey_base_new.clone()),
			self.params
		)?;

		let privkey_bits = boolean::field_into_boolean_vec_le(
			cs.namespace(|| "private key"),
			self.get_assigned(|assigned| assigned.privkey)
		)?;

		let pubkey_raised_old = pubkey_base_old.mul(
			cs.namespace(|| "old pubkey raised point"),
			&privkey_bits,
			self.params
		)?;
		let pubkey_raised_new = pubkey_base_new.mul(
			cs.namespace(|| "new pubkey raised point"),
			&privkey_bits,
			self.params
		)?;

		// Since raised pubkey points are computed by multiplication with the old pubkey points, if
		// the raised points are not low order, then the base points must not be either.
		pubkey_raised_old.assert_not_small_order(
			cs.namespace(|| "old pubkey raised point order check"),
			self.params
		)?;
		pubkey_raised_new.assert_not_small_order(
			cs.namespace(|| "new pubkey raised point order check"),
			self.params
		)?;

		let pubkey_base_old_bits = pubkey_base_old.repr(
			cs.namespace(|| "old pubkey base point bits")
		)?;
		let pubkey_raised_old_bits = pubkey_raised_old.repr(
			cs.namespace(|| "old pubkey raised point bits")
		)?;

		// Booleanize the coin position into little-endian bit order.
		let position_bits = boolean::u64_into_boolean_vec_le(
			cs.namespace(|| "position"),
			self.get_assigned(|assigned| assigned.position)
		)?;

		// Compute the encoding of the coin being spent.
		let encoded_coin_bits = position_bits.iter()
			.chain(value_comm_old_bits.iter())
			.chain(pubkey_base_old_bits.iter())
			.chain(pubkey_raised_old_bits.iter())
			.cloned()
			.collect::<Vec<_>>();

		let leaf = pedersen_hash::pedersen_hash(
			cs.namespace(|| "computation of leaf hash"),
			pedersen_hash::Personalization::NoteCommitment,
			&encoded_coin_bits,
			self.params
		)?.get_x().clone(); // Injective encoding

		// This is an injective encoding, as cur is a
		// point in the prime order subgroup.
		let mut cur = leaf;

		// Ascend the merkle tree authentication path.
		for i in 0..self.merkle_depth {
			let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

			// Witness the authentication path element adjacent at this depth.
			let path_element_value = self.assigned.as_ref()
				.and_then(|assigned| assigned.auth_path.get(i).cloned());
			let path_element = num::AllocatedNum::alloc(
				cs.namespace(|| "path element"),
				|| path_element_value.ok_or(SynthesisError::AssignmentMissing)
			)?;

			// Determines if the current subtree is the "right" leaf at this
			// depth of the tree.
			let cur_is_right = &position_bits[i];

			// Swap the two if the current subtree is on the right.
			let (xl, xr) = num::AllocatedNum::conditionally_reverse(
				cs.namespace(|| "conditional reversal of preimage"),
				&cur,
				&path_element,
				cur_is_right
			)?;

			// We don't need to be strict, because the function is
			// collision-resistant. If the prover witnesses a congruency,
			// they will be unable to find an authentication path in the
			// tree with high probability.
			let mut preimage = vec![];
			preimage.extend(xl.into_bits_le(cs.namespace(|| "xl into bits"))?);
			preimage.extend(xr.into_bits_le(cs.namespace(|| "xr into bits"))?);

			// Compute the new subtree value.
			cur = pedersen_hash::pedersen_hash(
				cs.namespace(|| "computation of pedersen hash"),
				pedersen_hash::Personalization::MerkleTree(i),
				&preimage,
				self.params
			)?.get_x().clone(); // Injective encoding
		}

		let anchor = {
			// Allocate the "real" anchor that will be exposed.
			let anchor_value = self.get_assigned(|assigned| assigned.anchor);
			let anchor = num::AllocatedNum::alloc(
				cs.namespace(|| "anchor"),
				|| anchor_value.ok_or(SynthesisError::AssignmentMissing)
			)?;

			// (cur - rt) * value = 0
			// if value is zero, cur and rt can be different
			// if value is nonzero, they must be equal
			//
			// TODO: Maybe drop the ability to do dummy inputs.
			cs.enforce(
				|| "conditionally enforce correct root",
				|lc| lc + cur.get_variable() - anchor.get_variable(),
				|lc| lc + &value_num.lc(E::Fr::one()),
				|lc| lc
			);

			anchor
		};

		// Let's compute nullifier = BLAKE2s(privkey || position).
		let nullifier_preimage = privkey_bits.iter()
			.chain(position_bits.iter())
			.cloned()
			.chain(iter::repeat(boolean::Boolean::constant(false)).take(4))
			.collect::<Vec<_>>();

		assert_eq!(nullifier_preimage.len(), 320);

		let nullifier = blake2s::blake2s(
			cs.namespace(|| "nullifier computation"),
			&nullifier_preimage,
			constants::PRF_NF_PERSONALIZATION
		)?;

		// Expose the anchor.
		anchor.inputize(cs.namespace(|| "anchor input"))?;

		// Expose the commitment as an input to the circuit.
		value_comm_new.inputize(cs.namespace(|| "new value commitment input"))?;

		pubkey_base_new.inputize(cs.namespace(|| "new pubkey base point input"))?;
		pubkey_raised_new.inputize(cs.namespace(|| "new pubkey raised point input"))?;

		multipack::pack_into_inputs(cs.namespace(|| "pack nullifier"), &nullifier)?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::constants::MERKLE_DEPTH;

	use sapling_crypto::jubjub::JubjubBls12;
	// use sapling_crypto::circuit::test::TestConstraintSystem;
	use pairing::bls12_381::Bls12;

//	#[test]
//	fn print_circuit_sizes() {
//		fn count_constraints(
//			n_inputs: usize,
//			n_outputs: usize,
//			n_kernels: usize,
//			params: &JubjubBls12
//		) -> usize
//		{
//			let transaction = Circuit::without_assignment(params, MERKLE_DEPTH);
//
//			let mut cs = TestConstraintSystem::<Bls12>::new();
//			transaction.synthesize(&mut cs).unwrap();
//			cs.num_constraints()
//		}
//
//		let params = &JubjubBls12::new();
//
//		let combinations = [
//			(0, 0, 0),
//			(1, 0, 0),
//			(100, 0, 0),
//			(1, 0, 0),
//			(0, 100, 0),
//			(0, 0, 1),
//			(0, 0, 10),
//		];
//		for (n_inputs, n_outputs, n_kernels) in combinations.iter() {
//			let constraints = count_constraints(*n_inputs, *n_outputs, *n_kernels, params);
//			println!(
//				"inputs: {}, outputs: {}, kernels: {}, constraints: {}",
//				*n_inputs, *n_outputs, *n_kernels, constraints
//			)
//		}
//	}
}
