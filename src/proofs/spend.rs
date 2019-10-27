use crate::primitives::{Nullifier, Value, PRF_NF_PERSONALIZATION};

use bellman::{
	self, SynthesisError, ConstraintSystem,
	gadgets::{blake2s, boolean, num, multipack},
};
use ff::Field;
use std::iter;
use zcash_primitives::jubjub::{edwards, FixedGenerators, JubjubEngine, Unknown};
use zcash_proofs::circuit::{ecc, pedersen_hash};

#[derive(Clone)]
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

	fn get_assigned<T>(&self, f: impl FnOnce(&Assignment<E>) -> T) -> Option<T> {
		self.assigned.as_ref().map(f)
	}
}

impl<'a, E> Clone for Circuit<'a, E>
	where E: JubjubEngine
{
	fn clone(&self) -> Self {
		Circuit {
			params: self.params,
			merkle_depth: self.merkle_depth,
			assigned: self.assigned.clone(),
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
			self.get_assigned(|assigned| assigned.value_nonce_old.clone())
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
			preimage.extend(xl.to_bits_le(cs.namespace(|| "xl into bits"))?);
			preimage.extend(xr.to_bits_le(cs.namespace(|| "xr into bits"))?);

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
		let nullifier_preimage = privkey_bits.into_iter()
			.chain(iter::repeat(boolean::Boolean::constant(false)).take(4))
			.chain(position_bits.into_iter())
			.collect::<Vec<_>>();

		assert_eq!(nullifier_preimage.len(), 320);

		let nullifier = blake2s::blake2s(
			cs.namespace(|| "nullifier computation"),
			&nullifier_preimage,
			PRF_NF_PERSONALIZATION
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

	use crate::hasher::PedersenHasher;
	use crate::merkle_tree::IncrementalMerkleTree;
	use crate::primitives::{MERKLE_DEPTH, Coin, compute_nullifier, value_commitment};
	use crate::proofs::tests::spend_params;

	use bellman::{Circuit as CircuitT, gadgets::test::TestConstraintSystem, groth16};
	use ff::{PrimeField, ScalarEngine};
	use pairing::bls12_381::Bls12;
	use rand::{SeedableRng, rngs::StdRng, Rng};
	use zcash_primitives::jubjub::{JubjubBls12, JubjubParams};

	#[test]
	fn circuit_size() {
		let params = JubjubBls12::new();

		let circuit = Circuit {
			params: &params,
			merkle_depth: MERKLE_DEPTH,
			assigned: Some(Assignment {
				position: 0,
				value: 0,
				value_nonce_old: Field::one(),
				value_nonce_new: Field::one(),
				privkey: Field::one(),
				pubkey_base_old: params.generator(FixedGenerators::SpendingKeyGenerator).into(),
				pubkey_base_new: params.generator(FixedGenerators::SpendingKeyGenerator).into(),
				nullifier: Nullifier::default(),
				auth_path: vec![Field::one(); MERKLE_DEPTH],
				anchor: Field::one(),
			}),
		};

		let mut cs = TestConstraintSystem::<Bls12>::new();
		circuit.synthesize(&mut cs).unwrap();

		assert_eq!(cs.num_constraints(), 78109);
	}

	#[test]
	fn real_groth16_bls12() {
		let jubjub_params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);

		let generator = jubjub_params.generator(FixedGenerators::ProofGenerationKey);

		let mut value = 0;
		let mut value_nonce_old = <Bls12 as JubjubEngine>::Fs::zero();
		let mut privkey = <Bls12 as JubjubEngine>::Fs::zero();
		let mut pubkey_base_old = <edwards::Point<_, Unknown>>::zero();

		// Build an accumulator with random coins and choose one of them for the proof inputs.
		let position = 57;
		let mut merkle_tree = IncrementalMerkleTree::empty(
			MERKLE_DEPTH, <PedersenHasher<Bls12, _>>::new(&jubjub_params)
		);
		for i in 0..100 {
			let leaf_value = rng.gen::<Value>();
			let leaf_value_nonce = <Bls12 as JubjubEngine>::Fs::random(&mut rng);
			let leaf_privkey = <Bls12 as JubjubEngine>::Fs::random(&mut rng);
			let leaf_pubkey_base = <edwards::Point<_, Unknown>>::from(
				generator.mul(
					<Bls12 as JubjubEngine>::Fs::random(&mut rng).into_repr(),
					&jubjub_params,
				)
			);
			let leaf_pubkey_raised = leaf_pubkey_base.mul(leaf_privkey, &jubjub_params);
			let leaf_coin = Coin {
				position: i,
				value_comm: value_commitment(leaf_value, &leaf_value_nonce, &jubjub_params).into(),
				pubkey: (leaf_pubkey_base.clone(), leaf_pubkey_raised.clone()),
			};

			let mut encoded_coin = Vec::new();
			leaf_coin.write(&mut encoded_coin).unwrap();

			if i == position {
				value = leaf_value;
				value_nonce_old = leaf_value_nonce;
				privkey = leaf_privkey;
				pubkey_base_old = leaf_pubkey_base;
				merkle_tree.track_next_leaf();
			}
			merkle_tree.push_data(&encoded_coin);
		}

		let value_nonce_new = <Bls12 as JubjubEngine>::Fs::random(&mut rng);
		let pubkey_base_new = <edwards::Point<_, Unknown>>::from(
			generator.mul(
				<Bls12 as JubjubEngine>::Fs::random(&mut rng).into_repr(),
				&jubjub_params,
			)
		);
		let pubkey_raised_new = pubkey_base_new.mul(privkey, &jubjub_params);

		let value_comm_new = value_commitment::<Bls12>(value, &value_nonce_new, &jubjub_params);
		let nullifier = compute_nullifier(&privkey, position);
		let auth_path = merkle_tree.tracked_branch(position)
			.unwrap()
			.iter()
			.map(|hash| <Bls12 as ScalarEngine>::Fr::from_repr(*hash).unwrap())
			.collect::<Vec<_>>();
		let anchor = <Bls12 as ScalarEngine>::Fr::from_repr(merkle_tree.root()).unwrap();

		let (value_comm_new_x, value_comm_new_y) = value_comm_new.to_xy();
		let (pubkey_base_new_x, pubkey_base_new_y) = pubkey_base_new.to_xy();
		let (pubkey_raised_new_x, pubkey_raised_new_y) = pubkey_raised_new.to_xy();
		let nullifier_bits = multipack::bytes_to_bits_le(&nullifier[..]);

		let assignment = Assignment {
			position,
			value,
			value_nonce_old,
			value_nonce_new,
			privkey,
			pubkey_base_old,
			pubkey_base_new,
			nullifier,
			auth_path,
			anchor,
		};
		let circuit = Circuit {
			params: &jubjub_params,
			merkle_depth: MERKLE_DEPTH,
			assigned: Some(assignment.clone()),
		};

		let proof_params = spend_params().unwrap();
		let verifying_key = groth16::prepare_verifying_key(&proof_params.vk);

		let proof = groth16::create_random_proof(circuit, &proof_params, None, &mut rng)
			.unwrap();

		let mut public_inputs = vec![
			assignment.anchor,
			value_comm_new_x, value_comm_new_y,
			pubkey_base_new_x, pubkey_base_new_y,
			pubkey_raised_new_x, pubkey_raised_new_y,
		];
		public_inputs.extend(multipack::compute_multipacking::<Bls12>(&nullifier_bits));
		assert!(groth16::verify_proof(&verifying_key, &proof, &public_inputs[..]).unwrap());
	}
}
