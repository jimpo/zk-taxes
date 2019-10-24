use bellman::{
	self, ConstraintSystem, SynthesisError,
	gadgets::boolean,
};
use zcash_primitives::jubjub::{edwards, FixedGenerators, JubjubEngine, Unknown};
use zcash_proofs::circuit::ecc;

#[derive(Clone)]
pub struct Assignment<E>
	where E: JubjubEngine
{
	pub nonce: E::Fs,
	pub k_g3: edwards::Point<E, Unknown>,
	pub tracing_pubkey: edwards::Point<E, Unknown>,
}

pub struct Circuit<'a, E>
	where E: JubjubEngine,
{
	pub params: &'a E::Params,
	pub assigned: Option<Assignment<E>>,
}

impl<'a, E> Clone for Circuit<'a, E>
	where E: JubjubEngine
{
	fn clone(&self) -> Self {
		Circuit {
			params: self.params.clone(),
			assigned: self.assigned.clone(),
		}
	}
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

impl<'a, E> bellman::Circuit<E> for Circuit<'a, E>
	where E: JubjubEngine,
{
	fn synthesize<CS>(self, cs: &mut CS) -> Result<(), SynthesisError>
		where CS: ConstraintSystem<E>
	{
		// Witness all of the curve point inputs.
		let k_g3 = ecc::EdwardsPoint::witness(
			cs.namespace(|| "credential id K"),
			self.get_assigned(|assigned| assigned.k_g3.clone()),
			self.params
		)?;
		let tracing_pubkey = ecc::EdwardsPoint::witness(
			cs.namespace(|| "tracing pubkey"),
			self.get_assigned(|assigned| assigned.tracing_pubkey.clone()),
			self.params
		)?;

		// Witness the nonce as a bit vector.
		let nonce_bits = boolean::field_into_boolean_vec_le(
			cs.namespace(|| "nonce"),
			self.get_assigned(|assigned| assigned.nonce.clone())
		)?;

		// Compute the pubkey from the generator, K, and the nonce.
		// P = (G3^n, K^n)
		let pubkey_base = ecc::fixed_base_multiplication(
			cs.namespace(|| "pubkey base point"),
			FixedGenerators::ProofGenerationKey,
			&nonce_bits,
			self.params
		)?;
		let pubkey_raised = k_g3.mul(
			cs.namespace(|| "pubkey raised point"),
			&nonce_bits,
			self.params
		)?;

		// Compute the tracing tag.
		// τ = K * T^n
		let tracing_tag = tracing_pubkey
			.mul(
				cs.namespace(|| "tracing tag T^n"),
				&nonce_bits,
				self.params
			)?
			.add(
				cs.namespace(|| "tracing tag K * T^n"),
				&k_g3,
				self.params
			)?;

		// Ensure that x coordinate of K is even.
		let x_bits = k_g3.get_x().to_bits_le_strict(cs.namespace(|| "K x coordinate bits"))?;

		boolean::Boolean::enforce_equal(
			cs.namespace(|| "enforce x coordinate of K is even"),
			&x_bits[0],
			&boolean::Boolean::constant(false),
		)?;

		// Input the user_id as a hybrid proof input.
		let user_id = cs.alloc_hybrid(
			|| "user id",
			|| {
				self.get_assigned(|assigned| assigned.k_g3.to_xy().1)
					.ok_or(SynthesisError::AssignmentMissing)
			}
		)?;
		cs.enforce(
			|| "enforce user id is y-coordinate of witness point",
			|lc| lc + user_id,
			|lc| lc + CS::one(),
			|lc| lc + k_g3.get_y().get_variable(),
		);

		pubkey_base.inputize(cs.namespace(|| "pubkey base input"))?;
		pubkey_raised.inputize(cs.namespace(|| "pubkey raised input"))?;
		tracing_pubkey.inputize(cs.namespace(|| "tracing pubkey input"))?;
		tracing_tag.inputize(cs.namespace(|| "tracing tag input"))?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::proofs::tests::certificate_params;

	use bellman::{
		Circuit as CircuitT,
		gadgets::test::TestConstraintSystem, groth16,
	};
	use ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
	use rand::{SeedableRng, rngs::StdRng};
	use pairing::bls12_381::Bls12;
	use zcash_primitives::jubjub::{JubjubBls12, JubjubParams};

	#[test]
	fn circuit_size() {
		let params = JubjubBls12::new();

		let circuit = Circuit {
			params: &params,
			assigned: Some(Assignment {
				nonce: Field::one(),
				k_g3: params.generator(FixedGenerators::SpendingKeyGenerator).into(),
				tracing_pubkey: params.generator(FixedGenerators::NullifierPosition).into(),
			}),
		};

		let mut cs = TestConstraintSystem::<Bls12>::new();
		circuit.synthesize(&mut cs).unwrap();

		assert_eq!(cs.num_constraints(), 7944);
	}

	#[test]
	fn real_groth16_bls12() {
		let jubjub_params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);

		let generator = jubjub_params.generator(FixedGenerators::ProofGenerationKey);
		let mut key = <Bls12 as JubjubEngine>::Fs::random(&mut rng);
		let tracing_key = <Bls12 as JubjubEngine>::Fs::random(&mut rng);
		let nonce = <Bls12 as JubjubEngine>::Fs::random(&mut rng);

		let mut pubkey = generator.mul(key.into_repr(), &jubjub_params);

		// Ensure sign of x is even.
		if pubkey.to_xy().0.into_repr().is_odd() {
			key.negate();
			pubkey = pubkey.negate();
		}

		let pubkey_base = generator.mul(nonce.into_repr(), &jubjub_params);
		let pubkey_raised = pubkey.mul(nonce.into_repr(), &jubjub_params);
		let tracing_pubkey = generator.mul(tracing_key.into_repr(), &jubjub_params);
		let tracing_tag = tracing_pubkey
			.mul(nonce, &jubjub_params)
			.add(&pubkey, &jubjub_params);

		let (pubkey_x, pubkey_y) = pubkey.to_xy();
		let (pubkey_base_x, pubkey_base_y) = pubkey_base.to_xy();
		let (pubkey_raised_x, pubkey_raised_y) = pubkey_raised.to_xy();
		let (tracing_pubkey_x, tracing_pubkey_y) = tracing_pubkey.to_xy();
		let (tracing_tag_x, tracing_tag_y) = tracing_tag.to_xy();

		let assignment = Assignment {
			nonce,
			k_g3: pubkey.into(),
			tracing_pubkey: tracing_pubkey.into(),
		};
		let circuit = Circuit {
			params: &jubjub_params,
			assigned: Some(assignment.clone()),
		};

		let proof_params = certificate_params().unwrap();
		let verifying_key = groth16::prepare_verifying_key(&proof_params.vk);

		let q = <Bls12 as ScalarEngine>::Fr::random(&mut rng);
		let proof = groth16::create_random_proof(circuit, &proof_params, Some(q), &mut rng)
			.unwrap();

		let public_inputs = [
			pubkey_base_x, pubkey_base_y,
			pubkey_raised_x, pubkey_raised_y,
			tracing_pubkey_x, tracing_pubkey_y,
			tracing_tag_x, tracing_tag_y,
		];
		assert!(groth16::verify_proof(&verifying_key, &proof, &public_inputs[..]).unwrap());
	}
}
