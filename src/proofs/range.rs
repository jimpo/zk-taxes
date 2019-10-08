use crate::transaction::Value;

use bellman::{self, SynthesisError, ConstraintSystem, gadgets::{boolean, num}};
use zcash_primitives::jubjub::{edwards, FixedGenerators, JubjubEngine, Unknown};
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

	use bellman::{
		Circuit as CircuitT,
		gadgets::test::TestConstraintSystem
	};
	use ff::Field;
	use pairing::bls12_381::Bls12;
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

		assert_eq!(cs.num_constraints(), 7942);
	}
}
