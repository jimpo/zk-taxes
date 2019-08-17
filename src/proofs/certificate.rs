use bellman::{
	self, ConstraintSystem, SynthesisError,
	gadgets::boolean,
};
use ff::Field;
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
			self.assigned.as_ref().map(|assigned| assigned.nonce.clone())
		)?;

		// Compute the pubkey from the generator, K, and the nonce.
		// P = (G3^n, K^n)
		let pubkey_base = ecc::fixed_base_multiplication(
			cs.namespace(|| "pubkey base point"),
			FixedGenerators::SpendingKeyGenerator,
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
		let x_bits = k_g3.get_x().into_bits_le_strict(cs.namespace(|| "K x coordinate bits"))?;

		boolean::Boolean::enforce_equal(
			cs.namespace(|| "enforce x coordinate of K is even"),
			&x_bits[0],
			&boolean::Boolean::constant(false),
		)?;

		// TODO: This should not be a public input, it should be a hybrid input.
		k_g3.get_y().inputize(cs.namespace(|| "K y coordinate hybrid input"));

		pubkey_base.inputize(cs.namespace(|| "pubkey base input"))?;
		pubkey_raised.inputize(cs.namespace(|| "pubkey raised input"))?;
		tracing_pubkey.inputize(cs.namespace(|| "tracing tag input"))?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use bellman::{
		Circuit as CircuitT,
		gadgets::test::TestConstraintSystem
	};
	use pairing::bls12_381::Bls12;
	use zcash_primitives::jubjub::{JubjubBls12, JubjubParams};

	#[test]
	fn circuit_size() {
		let params = JubjubBls12::new();

		let circuit = Circuit {
			params: &params,
			assigned: Some(Assignment {
				nonce: Field::one(),
				k_g3: params.generator(FixedGenerators::ProofGenerationKey).into(),
				tracing_pubkey: params.generator(FixedGenerators::NullifierPosition).into(),
			}),
		};

		let mut cs = TestConstraintSystem::<Bls12>::new();
		circuit.synthesize(&mut cs).unwrap();

		assert_eq!(cs.num_constraints(), 7942);
	}
}
