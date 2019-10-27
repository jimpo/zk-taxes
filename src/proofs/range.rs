use crate::primitives::Value;

use bellman::{self, SynthesisError, ConstraintSystem, gadgets::boolean};
use zcash_primitives::jubjub::{FixedGenerators, JubjubEngine};
use zcash_proofs::circuit::ecc;

#[derive(Clone)]
pub struct Assignment<E>
	where E: JubjubEngine
{
	pub value: Value,
	pub nonce: E::Fs,
}

pub struct Circuit<'a, E>
	where E: JubjubEngine,
{
	pub params: &'a E::Params,
	pub assigned: Option<Assignment<E>>,
}

impl<'a, E> Circuit<'a, E>
	where E: JubjubEngine,
{
	pub fn without_assignment(params: &'a E::Params) -> Self {
		Circuit {
			params,
			assigned: None,
		}
	}

	fn get_assigned<T>(&self, f: impl FnOnce(&Assignment<E>) -> T) -> Option<T> {
		self.assigned.as_ref().map(f)
	}
}

impl<'a, E> Clone for Circuit<'a, E>
	where E: JubjubEngine,
{
	fn clone(&self) -> Self {
		Circuit {
			params: self.params,
			assigned: self.assigned.clone(),
		}
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

		// Compute the value in the exponent.
		let value_pt = ecc::fixed_base_multiplication(
			cs.namespace(|| "compute the value in the exponent"),
			FixedGenerators::ValueCommitmentValue,
			&value_bits,
			self.params
		)?;

		// Booleanize the nonce. This does not ensure the bit representation is "in the field"
		// because it doesn't matter for security.
		let nonce_bits = boolean::field_into_boolean_vec_le(
			cs.namespace(|| "nonce"),
			self.get_assigned(|assigned| assigned.nonce.clone())
		)?;

		// Compute the nonce in the exponent.
		let nonce_pt = ecc::fixed_base_multiplication(
			cs.namespace(|| "compute the nonce in the exponent"),
			FixedGenerators::ValueCommitmentRandomness,
			&nonce_bits,
			self.params
		)?;

		// Compute the Pedersen commitment.
		let comm = value_pt.add(
			cs.namespace(|| "value commitment"),
			&nonce_pt,
			self.params
		)?;

		// Expose the Pedersen commitment.
		comm.inputize(cs.namespace(|| "commitment input"))?;

		Ok(())
	}
}


#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitives::value_commitment;
	use crate::proofs::tests::range_params;

	use bellman::{Circuit as CircuitT, gadgets::test::TestConstraintSystem, groth16};
	use ff::Field;
	use pairing::bls12_381::Bls12;
	use rand::{SeedableRng, rngs::StdRng, Rng};
	use zcash_primitives::jubjub::JubjubBls12;

	#[test]
	fn circuit_size() {
		let params = JubjubBls12::new();

		let circuit = Circuit {
			params: &params,
			assigned: Some(Assignment {
				value: 1,
				nonce: Field::one(),
			}),
		};

		let mut cs = TestConstraintSystem::<Bls12>::new();
		circuit.synthesize(&mut cs).unwrap();

		assert_eq!(cs.num_constraints(), 1265);
	}

	#[test]
	fn real_groth16_bls12() {
		let jubjub_params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);

		let value = rng.gen::<Value>();
		let nonce = <Bls12 as JubjubEngine>::Fs::random(&mut rng);
		let commitment = value_commitment::<Bls12>(value, &nonce, &jubjub_params);

		let assignment = Assignment {
			value,
			nonce,
		};
		let circuit = Circuit {
			params: &jubjub_params,
			assigned: Some(assignment.clone()),
		};

		let proof_params = range_params().unwrap();
		let verifying_key = groth16::prepare_verifying_key(&proof_params.vk);

		let proof = groth16::create_random_proof(circuit, &proof_params, None, &mut rng)
			.unwrap();

		let (commitment_x, commitment_y) = commitment.to_xy();
		let public_inputs = [
			commitment_x, commitment_y,
		];
		assert!(groth16::verify_proof(&verifying_key, &proof, &public_inputs[..]).unwrap());
	}
}
