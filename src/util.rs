use crate::codec::{Encode, write_prime_field_le};
use crate::constants;
use crate::transaction::{Value, Nullifier};

use blake2s_simd::Params as Blake2sParams;
use ff::PrimeField;
use zcash_primitives::{
	jubjub::{edwards, FixedGenerators, JubjubEngine, JubjubParams, PrimeOrder},
};

pub fn value_commitment<E>(value: Value, nonce: &E::Fs, params: &E::Params)
	-> edwards::Point<E, PrimeOrder>
	where E: JubjubEngine
{
	let g = params.generator(FixedGenerators::ValueCommitmentValue);
	let h = params.generator(FixedGenerators::ValueCommitmentRandomness);
	g.mul(value, params).add(&h.mul(nonce.into_repr(), params), params)
}

pub fn compute_nullifier<PF>(privkey: &PF, position: u64) -> Nullifier
	where PF: PrimeField
{
	let mut hasher = Blake2sParams::new()
		.hash_length(32)
		.personal(constants::PRF_NF_PERSONALIZATION)
		.to_state();
	write_prime_field_le(&mut hasher, privkey)
		.expect("writing to hasher cannot return an error");
	position.write(&mut hasher)
		.expect("writing to hasher cannot return an error");
	*hasher.finalize().as_array()
}
