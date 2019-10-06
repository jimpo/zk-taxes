use bellman::groth16::{create_random_proof, ParameterSource};
use blake2::{Blake2s, Digest};
use byteorder::{LittleEndian, ByteOrder};
use ff::{Field, PrimeField, PrimeFieldRepr};
use pairing::Engine;
use rand::RngCore;
use std::fmt::{self, Display, Formatter};
use std::mem::size_of;
use zcash_primitives::jubjub::{edwards, FixedGenerators, JubjubEngine, JubjubParams, Unknown, PrimeOrder};

use crate::constants::MERKLE_DEPTH;
use crate::hasher::{PedersenHasher, MerkleHasher};
use crate::proofs::spend;
use crate::transaction::{
	BlockNumber, Coin, Nullifier, Transaction, TransactionInput, TransactionOutput, Value,
};
use crate::validation;
use crate::merkle_tree::IncrementalMerkleTree;
use bellman::SynthesisError;

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
	where E: JubjubEngine
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

impl<E> TransactionDesc<E>
	where E: JubjubEngine
{
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
	)
		-> Result<UnprovenTransaction<E, BN>, Error<BN>>
		where
			BN: BlockNumber,
			R: RngCore,
	{
		self.check_values_balance()?;

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

				Ok(UnprovenTransactionInput {
					value_comm: value_commitment(input.value, &nonce, params).into(),
					pubkey: (pubkey_base, pubkey_raised),
					nullifier,
					proof_assignment: assignment,
				})
			})
			.collect::<Result<Vec<_>, _>>()?;
		let outputs = self.outputs.into_iter().zip(output_nonces.into_iter())
			.map(|(output, nonce)| UnprovenTransactionOutput {
				value_comm: value_commitment(output.value, &nonce, params).into(),
			})
			.collect::<Vec<_>>();

		Ok(UnprovenTransaction {
			inputs,
			outputs,
			issuance: self.issuance,
			accumulator_state_block_number: block_number,
		})
	}
}

impl<E> TransactionInputDesc<E>
	where E: JubjubEngine
{
	pub fn coin(&self, params: &E::Params) -> Coin<E> {
		let pubkey_base_point = self.pubkey_base.clone();
		let pubkey_raised_point = pubkey_base_point.mul(self.privkey.into_repr(), params);
		Coin {
			position: self.position,
			value_comm: value_commitment(self.value, &self.value_nonce, params).into(),
			pubkey: (pubkey_base_point, pubkey_raised_point),
		}
	}
}

pub struct UnprovenTransaction<E, BN>
	where
		E: JubjubEngine,
		BN: BlockNumber,
{
	pub inputs: Vec<UnprovenTransactionInput<E>>,
	pub outputs: Vec<UnprovenTransactionOutput<E>>,
	pub issuance: i64,

	/// The state of the coin accumulator used to validate inputs
	pub accumulator_state_block_number: BN,
}

impl<E, BN> UnprovenTransaction<E, BN>
	where
		E: JubjubEngine,
		BN: BlockNumber,
{
	fn validate_assignments(
		&self,
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E>>,
		params: &<E as JubjubEngine>::Params,
	) -> Result<(), &str>
	{
		for input in self.inputs.iter() {
			input.validate_assignment(merkle_tree, params)?;
		}
		Ok(())
	}
}

#[derive(Clone)]
pub struct UnprovenTransactionInput<E>
	where E: JubjubEngine
{
	pub value_comm: edwards::Point<E, Unknown>,
	pub pubkey: (edwards::Point<E, Unknown>, edwards::Point<E, Unknown>),
	pub nullifier: Nullifier,
	pub proof_assignment: spend::Assignment<E>,
}

impl<E> UnprovenTransactionInput<E>
	where E: JubjubEngine
{
	fn validate_assignment(
		&self,
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E>>,
		params: &<E as JubjubEngine>::Params
	) -> Result<(), &str>
	{
		let assigned = &self.proof_assignment;

		let value_comm_old = value_commitment(
			assigned.value, &assigned.value_nonce_old, params
		);
		let value_comm_new = value_commitment(
			assigned.value, &assigned.value_nonce_new, params
		);

		if self.value_comm != value_comm_new.into() {
			return Err("value commitment mismatch");
		}

		let pubkey_raised_old = assigned.pubkey_base_old.mul(assigned.privkey.into_repr(), params);
		let pubkey_raised_new = assigned.pubkey_base_new.mul(assigned.privkey.into_repr(), params);

		if self.pubkey.0 != assigned.pubkey_base_new {
			return Err("pubkey base point mismatch");
		}
		if self.pubkey.1 != pubkey_raised_new {
			return Err("pubkey raised point mismatch");
		}

		if is_low_order(&pubkey_raised_old, params) {
			return Err("old pubkey is low order");
		}
		if is_low_order(&pubkey_raised_new, params) {
			return Err("new pubkey is low order");
		}

		let coin_old = Coin {
			position: assigned.position,
			value_comm: value_comm_old.into(),
			pubkey: (assigned.pubkey_base_old.clone(), pubkey_raised_old),
		};

		let mut encoded_coin = Vec::new();
		coin_old.write(&mut encoded_coin)
			.expect("can always write to a new Vec");

		let leaf = merkle_tree.hasher().hash_leaf(&encoded_coin);
		let branch = assigned.auth_path.iter()
			.map(|node| node.into_repr())
			.collect::<Vec<_>>();

		let anchor_is_valid = merkle_tree.check_branch_against_root(
			assigned.position,
			&leaf,
			&branch,
			&assigned.anchor.into_repr()
		);
		if !anchor_is_valid {
			return Err("merkle root mismatch");
		}

		if assigned.nullifier != compute_nullifier::<E>(&assigned.privkey, assigned.position) {
			return Err("nullifier mismatch");
		}

		Ok(())
	}
}

pub struct UnprovenTransactionOutput<E>
	where E: JubjubEngine
{
	pub value_comm: edwards::Point<E, Unknown>,
}

impl<E, BN> UnprovenTransaction<E, BN>
	where
		E: JubjubEngine,
		BN: BlockNumber,
{
	pub fn prove<P, R>(self, params: &E::Params, spend_proof_params: P, rng: &mut R)
		-> Result<Transaction<E, BN>, SynthesisError>
		where
			P: ParameterSource<E> + Clone,
			R: RngCore,
	{
		let inputs = self.inputs.into_iter()
			.map(|input| input.prove(params, spend_proof_params.clone(), rng))
			.collect::<Result<Vec<_>, SynthesisError>>()?;
		let outputs = self.outputs.into_iter()
			.map(|output| output.prove(params, rng))
			.collect::<Result<Vec<_>, SynthesisError>>()?;

		Ok(Transaction {
			inputs,
			outputs,
			issuance: self.issuance,
			accumulator_state_block_number: self.accumulator_state_block_number,
		})
	}
}

impl<E> UnprovenTransactionInput<E>
	where E: JubjubEngine
{
	pub fn prove<P, R>(self, params: &E::Params, spend_proof_params: P, rng: &mut R)
		-> Result<TransactionInput<E>, SynthesisError>
		where
			P: ParameterSource<E>,
			R: RngCore,
	{
		let circuit = spend::Circuit {
			params,
			merkle_depth: MERKLE_DEPTH,
			assigned: Some(self.proof_assignment),
		};
		let proof = create_random_proof(circuit, spend_proof_params, None, rng)?;
		Ok(TransactionInput {
			value_comm: self.value_comm,
			pubkey: self.pubkey,
			nullifier: self.nullifier,
			proof,
		})
	}

}

impl<E> UnprovenTransactionOutput<E>
	where E: JubjubEngine
{
	pub fn prove<R>(self, _params: &E::Params, _rng: &mut R)
		-> Result<TransactionOutput<E>, SynthesisError>
		where R: RngCore
	{
		Ok(TransactionOutput {
			value_comm: self.value_comm,
		})
	}
}

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

fn value_commitment<E>(value: Value, nonce: &E::Fs, params: &E::Params)
	-> edwards::Point<E, PrimeOrder>
	where E: JubjubEngine
{
	let g = params.generator(FixedGenerators::ValueCommitmentValue);
	let h = params.generator(FixedGenerators::ValueCommitmentRandomness);
	g.mul(value, params).add(&h.mul(nonce.into_repr(), params), params)
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
	use zcash_primitives::jubjub::{edwards, FixedGenerators, JubjubBls12};

	use crate::proofs;
	use crate::validation;

	fn add_input<E>(
		merkle_tree: &mut IncrementalMerkleTree<PedersenHasher<E>>,
		input: &TransactionInputDesc<E>,
		params: &E::Params,
	)
		where E: JubjubEngine
	{
		let mut encoded_coin = Vec::new();
		input.coin(params).write(&mut encoded_coin).unwrap();

		merkle_tree.track_next_leaf();
		merkle_tree.push_data(&encoded_coin);
	}

	#[test]
	fn build_empty_transaction() {
		let params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);
		let block_number = 42;
		let mut merkle_tree = IncrementalMerkleTree::empty(
			MERKLE_DEPTH, PedersenHasher::new(&params)
		);

		let tx_desc = TransactionDesc::<Bls12> {
			inputs: vec![],
			outputs: vec![],
			issuance: 0,
		};

		let tx = tx_desc.build(
			block_number,
			&merkle_tree,
			&params,
			&mut rng
		).unwrap();

		tx.validate_assignments(&merkle_tree, &params).unwrap();
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
		let mut merkle_tree = IncrementalMerkleTree::empty(
			MERKLE_DEPTH, PedersenHasher::new(&params)
		);

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

		for input in tx_desc.inputs.iter() {
			add_input(&mut merkle_tree, input, &params);
		}

		let tx = tx_desc.build(
			block_number,
			&merkle_tree,
			&params,
			&mut rng
		).unwrap();

		tx.validate_assignments(&merkle_tree, &params).unwrap();
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
		let mut merkle_tree = IncrementalMerkleTree::empty(
			MERKLE_DEPTH, PedersenHasher::new(&params)
		);

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

		for input in tx_desc.inputs.iter() {
			add_input(&mut merkle_tree, input, &params);
		}

		let tx = tx_desc.build(
			block_number,
			&merkle_tree,
			&params,
			&mut rng
		).unwrap();

		tx.validate_assignments(&merkle_tree, &params).unwrap();
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
		let mut merkle_tree = IncrementalMerkleTree::empty(
			MERKLE_DEPTH, PedersenHasher::new(&params)
		);

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
		let tx = tx_desc.build(
			block_number,
			&merkle_tree,
			&params,
			&mut rng
		).unwrap();

		tx.validate_assignments(&merkle_tree, &params).unwrap();
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
		let mut merkle_tree = IncrementalMerkleTree::empty(
			MERKLE_DEPTH, PedersenHasher::new(&params)
		);

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

		for input in tx_desc.inputs.iter() {
			add_input(&mut merkle_tree, input, &params);
		}

		let err = tx_desc.build(
			block_number,
			&merkle_tree,
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
		let mut merkle_tree = IncrementalMerkleTree::empty(
			MERKLE_DEPTH, PedersenHasher::new(&params)
		);

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

		let err = tx_desc.build(
			block_number,
			&merkle_tree,
			&params,
			&mut rng
		).err().unwrap();

		assert_eq!(err, Error::Validation(validation::Error::UnbalancedTransaction));
	}

	#[test]
	fn transaction_with_real_proofs() {
		let params = JubjubBls12::new();
		let mut rng = StdRng::seed_from_u64(0);
		let block_number = 42;
		let mut merkle_tree = IncrementalMerkleTree::empty(
			MERKLE_DEPTH, PedersenHasher::new(&params)
		);

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

		for input in tx_desc.inputs.iter() {
			add_input(&mut merkle_tree, input, &params);
		}

		let proof_params = proofs::tests::spend_params().unwrap();
		let tx = tx_desc.build(
			block_number,
			&merkle_tree,
			&params,
			&mut rng
		).unwrap();
		let tx = tx.prove(&params, &proof_params, &mut rng).unwrap();

		assert_eq!(tx.inputs.len(), 2);
		assert_eq!(tx.outputs.len(), 2);
		assert_eq!(tx.issuance, 400_000);
		assert_eq!(tx.accumulator_state_block_number, block_number);
	}
}
