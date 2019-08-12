use bellman::groth16::{ParameterSource, create_random_proof, Proof};
use blake2::{Blake2s, Digest};
use byteorder::{LittleEndian, ByteOrder};
use ff::{Field, PrimeField, PrimeFieldRepr};
use group::CurveAffine;
use pairing::Engine;
use rand::RngCore;
use sapling_crypto::jubjub::{edwards, FixedGenerators, JubjubEngine, JubjubParams, Unknown};
use std::fmt::{self, Display, Formatter};
use std::mem::size_of;

use crate::constants::MERKLE_DEPTH;
use crate::hasher::{PedersenHasher, MerkleHasher};
use crate::proofs::spend;
use crate::transaction::{
	BlockNumber, Coin, Nullifier, Transaction, TransactionInput, TransactionOutput, Value,
};
use crate::validation;
use crate::merkle_tree::IncrementalMerkleTree;

#[derive(Debug, PartialEq)]
pub enum Error<BN>
	where BN: BlockNumber,
{
	Validation(validation::Error<BN>),
	AccumulatorStateInvalid,
	ProofSynthesis(String),
}

impl<BN> Display for Error<BN>
	where BN: BlockNumber
{
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		match self {
			Error::Validation(e) => write!(f, "invalid transaction: {}", e),
			Error::AccumulatorStateInvalid => write!(f, "accumulator state is invalid"),
			Error::ProofSynthesis(e) => write!(f, "failed to construct proof: {}", e),
		}
	}
}

impl<BN> std::error::Error for Error<BN>
	where BN: BlockNumber
{}

pub struct TransactionDesc<E>
	where E: Engine + JubjubEngine
{
	pub inputs: Vec<TransactionInputDesc<E>>,
	pub outputs: Vec<TransactionOutputDesc>,
	pub issuance: i64,
}

pub struct TransactionInputDesc<E>
	where E: Engine + JubjubEngine
{
	pub position: u64,
	pub value: Value,
	pub value_nonce: E::Fs,
	pub privkey: E::Fs,
	pub pubkey_base: edwards::Point<E, Unknown>,
}

pub struct TransactionOutputDesc
{
	pub value: Value,
}

impl<E: Engine + JubjubEngine> TransactionDesc<E> {
	fn check_values_balance<BN>(&self) -> Result<(), Error<BN>>
		where BN: BlockNumber
	{
		let mut input_total = self.inputs.iter()
			.fold(Some(0u64), |sum, input| sum?.checked_add(input.value))
			.ok_or(Error::Validation(validation::Error::ValueOverflow))?;
		let mut output_total = self.outputs.iter()
			.fold(Some(0u64), |sum, output| sum?.checked_add(output.value))
			.ok_or(Error::Validation(validation::Error::ValueOverflow))?;
		if self.issuance.is_positive() {
			input_total = input_total.checked_add(self.issuance.abs() as u64)
				.ok_or(Error::Validation(validation::Error::ValueOverflow))?;
		} else {
			output_total = output_total.checked_add(self.issuance.abs() as u64)
				.ok_or(Error::Validation(validation::Error::ValueOverflow))?;
		}
		if input_total != output_total {
			return Err(Error::Validation(validation::Error::UnbalancedTransaction));
		}

		Ok(())
	}

	fn generate_nonces<R>(&self, rng: &mut R) -> (Vec<E::Fs>, Vec<E::Fs>)
		where R: RngCore
	{
		let mut input_nonces = self.inputs.iter()
			.map(|_| E::Fs::random(rng))
			.collect::<Vec<_>>();
		let mut output_nonces = self.outputs.iter()
			.map(|_| E::Fs::random(rng))
			.collect::<Vec<_>>();

		let mut nonce_sum = E::Fs::zero();
		for nonce in input_nonces.iter() {
			nonce_sum.add_assign(nonce);
		}
		for nonce in output_nonces.iter() {
			nonce_sum.sub_assign(nonce);
		}

		match (input_nonces.first_mut(), output_nonces.first_mut()) {
			(Some(nonce), _) => nonce.sub_assign(&nonce_sum),
			(_, Some(nonce)) => nonce.add_assign(&nonce_sum),
			_ => {}
		}

		(input_nonces, output_nonces)
	}

	pub fn build<'a, BN, R>(
		self,
		block_number: BN,
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E>>,
		params: &'a <E as JubjubEngine>::Params,
		rng: &'a mut R,
		prove_spend: impl Fn(spend::Assignment<E>, &mut R) -> Result<Proof<E>, String>,
	)
		-> Result<Transaction<E, BN>, Error<BN>>
		where
			BN: BlockNumber,
			R: RngCore,
	{
		self.check_values_balance()?;

		let p_g = <edwards::Point<E, Unknown>>::from(
			params.generator(FixedGenerators::ValueCommitmentValue).clone()
		);
		let p_h = <edwards::Point<E, Unknown>>::from(
			params.generator(FixedGenerators::ValueCommitmentRandomness).clone()
		);

		let commit = |val, key: E::Fs| {
			p_g.mul(val, params).add(&p_h.mul(key.into_repr(), params), params)
		};
		let (input_nonces, output_nonces) = self.generate_nonces(rng);
		let anchor = E::Fr::from_repr(merkle_tree.root())
			.map_err(|_| Error::AccumulatorStateInvalid)?;

		let inputs = self.inputs.into_iter().zip(input_nonces.into_iter())
			.map(|(input, nonce)| {
				let blinding_factor = E::Fs::random(rng);
				let pubkey_base = input.pubkey_base.mul(blinding_factor.into_repr(), params);
				let pubkey_raised = pubkey_base.mul(input.privkey.into_repr(), params);
				let nullifier = compute_nullifier::<E>(&input.privkey, input.position);
				let auth_path = merkle_tree.tracked_branch(input.position)
					.ok_or_else(|| {
						Error::ProofSynthesis("could not get auth path for input".to_string())
					})?;
				let auth_path = auth_path.iter()
					.map(|&repr| {
						E::Fr::from_repr(repr).map_err(|_| {
							Error::ProofSynthesis("Merkle branch hashes invalid".to_string())
						})
					})
					.collect::<Result<Vec<_>, _>>()?;

				let assignment = spend::Assignment {
					position: input.position,
					value: input.value,
					value_nonce_old: input.value_nonce,
					value_nonce_new: nonce,
					privkey: input.privkey,
					pubkey_base_old: input.pubkey_base,
					pubkey_base_new: pubkey_base.clone(),
					nullifier,
					auth_path,
					anchor,
				};
				let proof = prove_spend(assignment, rng)
					.map_err(|e| Error::ProofSynthesis(e))?;

				Ok(TransactionInput {
					value_comm: commit(input.value, nonce),
					nullifier,
					pubkey: (pubkey_base, pubkey_raised),
					proof,
				})
			})
			.collect::<Result<Vec<_>, _>>()?;
		let outputs = self.outputs.into_iter().zip(output_nonces.into_iter())
			.map(|(output, nonce)| TransactionOutput {
				value_comm: commit(output.value, nonce),
			})
			.collect::<Vec<_>>();

		Ok(Transaction {
			inputs,
			outputs,
			issuance: self.issuance,
			accumulator_state_block_number: block_number,
		})
	}

	pub fn build_with_real_proofs<BN, P, R>(
		self,
		block_number: BN,
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E>>,
		params: &<E as JubjubEngine>::Params,
		proof_params: P,
		rng: &mut R
	)
		-> Result<Transaction<E, BN>, Error<BN>>
		where
			BN: BlockNumber,
			R: RngCore,
			P: ParameterSource<E> + Clone,
	{
		let prove_spend = |assignment, rng: &mut R| {
			let circuit = spend::Circuit {
				params,
				merkle_depth: MERKLE_DEPTH,
				assigned: Some(assignment),
			};
			create_random_proof(circuit, proof_params.clone(), rng)
				.map_err(|e| e.to_string())
		};
		self.build(
			block_number,
			merkle_tree,
			params,
			rng,
			prove_spend
		)
	}

	pub fn build_with_dummy_proofs<BN, R>(
		self,
		block_number: BN,
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E>>,
		params: &<E as JubjubEngine>::Params,
		rng: &mut R
	)
		-> Result<Transaction<E, BN>, Error<BN>>
		where
			BN: BlockNumber,
			R: RngCore,
	{
		let prove_spend = |assigned: spend::Assignment<E>, _rng: &mut R| {
			// Double check that assignment is valid.
			let p_g = <edwards::Point<E, Unknown>>::from(
				params.generator(FixedGenerators::ValueCommitmentValue).clone()
			);
			let p_h = <edwards::Point<E, Unknown>>::from(
				params.generator(FixedGenerators::ValueCommitmentRandomness).clone()
			);
			let commit = |val, key: E::Fs| {
				p_g.mul(val, params).add(&p_h.mul(key.into_repr(), params), params)
			};

			let value_comm_old = commit(assigned.value, assigned.value_nonce_old);
			// let value_comm_new = commit(assigned.value, assigned.value_nonce_new);

			let pubkey_raised_old = assigned.pubkey_base_old.mul(assigned.privkey, params);
			let pubkey_raised_new = assigned.pubkey_base_new.mul(assigned.privkey, params);

			if is_low_order(&pubkey_raised_old, params) {
				return Err("old pubkey is low order".into());
			}
			if is_low_order(&pubkey_raised_new, params) {
				return Err("new pubkey is low order".into());
			}

			let coin_old = Coin {
				position: assigned.position,
				value_comm: value_comm_old,
				pubkey: (assigned.pubkey_base_old, pubkey_raised_old),
			};

			let mut encoded_coin = Vec::new();
			coin_old.write(&mut encoded_coin).map_err(|e| e.to_string())?;

			let hasher = <PedersenHasher<E>>::new(params);

			let mut merkle_node = hasher.hash_leaf(&encoded_coin);
			for (height, path_element) in assigned.auth_path.into_iter().enumerate() {
				let path_element = path_element.into_repr();
				let (left, right) = if assigned.position & (1 << height) == 0 {
					(&merkle_node, &path_element)
				} else {
					(&path_element, &merkle_node)
				};
				merkle_node = hasher.hash_internal(height, left, right);
			}

			if merkle_node != assigned.anchor.into_repr() {
				return Err("merkle root mismatch".into());
			}

			if assigned.nullifier != compute_nullifier::<E>(&assigned.privkey, assigned.position) {
				return Err("nullifier mismatch".into());
			}

			Ok(Proof {
				a: E::G1Affine::zero(),
				b: E::G2Affine::zero(),
				c: E::G1Affine::zero(),
			})
		};
		self.build(
			block_number,
			merkle_tree,
			params,
			rng,
			prove_spend
		)
	}
}
//
//fn field_element_read_le<F: PrimeField>(hash: &H256) -> Result<F, Error> {
//	let mut repr = F::Repr::default();
//	repr.read_le(hash.as_ref())
//		.expect("the field element representation is 32 bytes");
//	F::from_repr(repr.into())
//		.map_err(Into::into)
//}
//
//// TODO: Merge with same method in hasher.
//fn field_element_to_hash<F: PrimeField>(element: &F) -> H256 {
//	let mut hash = H256::default();
//	element.into_repr().write_le(hash.as_mut())
//		.expect("the field element representation is 32 bytes");
//	hash
//}

fn compute_nullifier<E>(privkey: &E::Fs, position: u64) -> Nullifier
	where E: JubjubEngine
{
	let mut preimage = Vec::new();
	privkey.into_repr().write_le(&mut preimage)
		.expect("writing to Vec should not fail");

	let index = preimage.len();
	preimage.resize(index + size_of::<u64>(), 0);
	LittleEndian::write_u64(&mut preimage[index..], position);

	let digest = Blake2s::digest(preimage.as_slice());

	let mut nullifier = Nullifier::default();
	&mut nullifier[..].copy_from_slice(digest.as_slice());
	nullifier
}

fn is_low_order<E>(pt: &edwards::Point<E, Unknown>, params: &E::Params) -> bool
	where E: JubjubEngine
{
	pt.mul_by_cofactor(params) == edwards::Point::zero()
}

#[cfg(test)]
mod tests {
	use super::*;

	use pairing::bls12_381::Bls12;
	use rand::{SeedableRng, rngs::StdRng};
	use sapling_crypto::jubjub::{edwards, FixedGenerators, JubjubBls12};

	use crate::validation::{self, AccumulatorState};

	impl BlockNumber for u64 {}

	#[test]
	fn build_empty_transaction() {
		let params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);
		let block_number = 42;

		let tx_desc = TransactionDesc::<Bls12> {
			inputs: vec![],
			outputs: vec![],
			issuance: 0,
		};

		let tx = tx_desc.build_with_dummy_proofs(
			block_number,
			<AccumulatorState<Bls12>>::default(),
			&params,
			&mut rng
		).unwrap();

		assert!(tx.inputs.is_empty());
		assert!(tx.outputs.is_empty());
		assert_eq!(tx.issuance, 0);
		assert_eq!(tx.accumulator_state_block_number, block_number);
	}

	#[test]
	fn build_transaction_with_inputs_and_outputs() {
		let params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);
		let block_number = 42;

		let tx_desc = TransactionDesc::<Bls12> {
			inputs: vec![
				TransactionInputDesc {
					position: 0,
					value: 100_000,
					value_nonce: <Bls12 as JubjubEngine>::Fs::zero(),
					privkey: <Bls12 as JubjubEngine>::Fs::one(),
					pubkey_base: params.generator(FixedGenerators::SpendingKeyGenerator).into(),
				},
				TransactionInputDesc {
					position: 1,
					value: 200_000,
					value_nonce: <Bls12 as JubjubEngine>::Fs::zero(),
					privkey: <Bls12 as JubjubEngine>::Fs::one(),
					pubkey_base: params.generator(FixedGenerators::SpendingKeyGenerator).into(),
				},
			],
			outputs: vec![
				TransactionOutputDesc {
					value: 300_000,
				},
				TransactionOutputDesc {
					value: 400_000,
				},
			],
			issuance: 400_000,
		};
		let tx = tx_desc.build_with_dummy_proofs(
			block_number,
			<AccumulatorState<Bls12>>::default(),
			&params,
			&mut rng
		).unwrap();

		assert_eq!(tx.inputs.len(), 2);
		assert_eq!(tx.outputs.len(), 2);
		assert_eq!(tx.issuance, 400_000);
		assert_eq!(tx.accumulator_state_block_number, block_number);
	}

	#[test]
	fn build_transaction_with_inputs_and_no_outputs() {
		let params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);
		let block_number = 42;

		let tx_desc = TransactionDesc::<Bls12> {
			inputs: vec![
				TransactionInputDesc {
					position: 0,
					value: 100_000,
					value_nonce: <Bls12 as JubjubEngine>::Fs::zero(),
					privkey: <Bls12 as JubjubEngine>::Fs::one(),
					pubkey_base: params.generator(FixedGenerators::SpendingKeyGenerator).into(),
				},
				TransactionInputDesc {
					position: 1,
					value: 200_000,
					value_nonce: <Bls12 as JubjubEngine>::Fs::zero(),
					privkey: <Bls12 as JubjubEngine>::Fs::one(),
					pubkey_base: params.generator(FixedGenerators::SpendingKeyGenerator).into(),
				},
			],
			outputs: vec![],
			issuance: -300_000,
		};
		let tx = tx_desc.build_with_dummy_proofs(
			block_number,
			<AccumulatorState<Bls12>>::default(),
			&params,
			&mut rng
		).unwrap();

		assert_eq!(tx.inputs.len(), 2);
		assert_eq!(tx.outputs.len(), 0);
		assert_eq!(tx.issuance, -300_000);
		assert_eq!(tx.accumulator_state_block_number, block_number);
	}

	#[test]
	fn build_transaction_with_outputs_and_no_inputs() {
		let params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);
		let block_number = 42;

		let tx_desc = TransactionDesc::<Bls12> {
			inputs: vec![],
			outputs: vec![
				TransactionOutputDesc {
					value: 300_000,
				},
				TransactionOutputDesc {
					value: 400_000,
				},
			],
			issuance: 700_000,
		};
		let tx = tx_desc.build_with_dummy_proofs(
			block_number,
			<AccumulatorState<Bls12>>::default(),
			&params,
			&mut rng
		).unwrap();

		assert_eq!(tx.inputs.len(), 0);
		assert_eq!(tx.outputs.len(), 2);
		assert_eq!(tx.issuance, 700_000);
		assert_eq!(tx.accumulator_state_block_number, block_number);
	}

	#[test]
	fn build_transaction_with_overflow() {
		let params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);
		let block_number = 42;

		let tx_desc = TransactionDesc::<Bls12> {
			inputs: vec![
				TransactionInputDesc {
					position: 0,
					value: std::u64::MAX,
					value_nonce: <Bls12 as JubjubEngine>::Fs::zero(),
					privkey: <Bls12 as JubjubEngine>::Fs::zero(),
					pubkey_base: edwards::Point::zero(),
				},
				TransactionInputDesc {
					position: 1,
					value: std::u64::MAX,
					value_nonce: <Bls12 as JubjubEngine>::Fs::zero(),
					privkey: <Bls12 as JubjubEngine>::Fs::zero(),
					pubkey_base: edwards::Point::zero(),
				},
			],
			outputs: vec![
				TransactionOutputDesc {
					value: std::u64::MAX,
				},
				TransactionOutputDesc {
					value: std::u64::MAX,
				},
			],
			issuance: 0,
		};

		let err = tx_desc.build_with_dummy_proofs(
			block_number,
			<AccumulatorState<Bls12>>::default(),
			&params,
			&mut rng
		).err().unwrap();

		assert_eq!(err, Error::Validation(validation::Error::ValueOverflow));
	}

	#[test]
	fn build_unbalanced_transaction() {
		let params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);
		let block_number = 42;

		let tx_desc = TransactionDesc::<Bls12> {
			inputs: vec![
				TransactionInputDesc {
					position: 0,
					value: 100_000,
					value_nonce: <Bls12 as JubjubEngine>::Fs::zero(),
					privkey: <Bls12 as JubjubEngine>::Fs::zero(),
					pubkey_base: edwards::Point::zero(),
				},
			],
			outputs: vec![
				TransactionOutputDesc {
					value: 200_000,
				},
			],
			issuance: 0,
		};

		let err = tx_desc.build_with_dummy_proofs(
			block_number,
			<AccumulatorState<Bls12>>::default(),
			&params,
			&mut rng
		).err().unwrap();

		assert_eq!(err, Error::Validation(validation::Error::UnbalancedTransaction));
	}
}
