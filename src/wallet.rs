/// Operations that a user performs locally to generate and identify transactions.

use bellman::{SynthesisError, groth16::create_random_proof};
use ff::{Field, PrimeField};
use pairing::Engine;
use rand::{CryptoRng, RngCore};
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;
use zcash_primitives::jubjub::{edwards, FixedGenerators, JubjubEngine, JubjubParams, Unknown};

use crate::certificate::{UserCredential, issue_certificate, verify_credential};
use crate::hasher::PedersenHasher;
use crate::merkle_tree::{MerkleHasher, IncrementalMerkleTree};
use crate::proofs::{range, spend};
use crate::primitives::{
	MERKLE_DEPTH,
	BlockNumber, Coin, Nullifier, Value,
	Transaction, TransactionInput, TransactionOutput, TransactionInputBundle,
	compute_nullifier, value_commitment,
};
use crate::validation::{self, PublicParams};

#[derive(Debug, PartialEq)]
pub enum Error {
	Validation(validation::Error),
	AccumulatorStateInvalid,
	ProofSynthesis(String),
}

impl Display for Error {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		match self {
			Error::Validation(e) => write!(f, "invalid transaction: {}", e),
			Error::AccumulatorStateInvalid => write!(f, "accumulator state is invalid"),
			Error::ProofSynthesis(e) => write!(f, "failed to construct proof: {}", e),
		}
	}
}

impl std::error::Error for Error {}

#[derive(Clone)]
pub struct TransactionDesc<E>
	where E: Engine + JubjubEngine
{
	pub inputs: Vec<TransactionInputBundleDesc<E>>,
	pub outputs: Vec<TransactionOutputDesc<E>>,
	pub issuance: i64,
}

#[derive(Clone)]
pub struct TransactionInputDesc<E>
	where E: JubjubEngine
{
	pub position: u64,
	pub value: Value,
	pub value_nonce: E::Fs,
	pub pubkey_base: edwards::Point<E, Unknown>,
}

impl<E> TransactionInputDesc<E>
	where E: JubjubEngine
{
	fn build<P>(
		self,
		nonce: E::Fs,
		privkey: &E::Fs,
		pubkey_base: &edwards::Point<E, Unknown>,
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E, P>>,
		params: &E::Params,
	)
		-> Result<UnprovenTransactionInput<E>, Error>
		where P: Deref<Target=E::Params>
	{
		let nullifier = compute_nullifier(privkey, self.position);
		let anchor = E::Fr::from_repr(merkle_tree.root())
			.map_err(|_| Error::AccumulatorStateInvalid)?;
		let auth_path = merkle_tree.tracked_branch(self.position)
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
			position: self.position,
			value: self.value,
			value_nonce_old: self.value_nonce,
			value_nonce_new: nonce,
			privkey: privkey.clone(),
			pubkey_base_old: self.pubkey_base,
			pubkey_base_new: pubkey_base.clone(),
			nullifier,
			auth_path,
			anchor,
		};

		Ok(UnprovenTransactionInput {
			value_comm: value_commitment(self.value, &nonce, params).into(),
			nullifier,
			proof_assignment: assignment,
		})
	}
}

#[derive(Clone)]
pub struct TransactionOutputDesc<E>
	where E: JubjubEngine
{
	pub value: Value,
	pub credential: UserCredential<E>,
}

impl<E> TransactionOutputDesc<E>
	where E: JubjubEngine
{
	fn build(self, nonce: E::Fs, params: &E::Params) -> UnprovenTransactionOutput<E> {
		UnprovenTransactionOutput {
			value_comm: value_commitment(self.value, &nonce, params).into(),
			credential: self.credential,
		}
	}
}

#[derive(Clone)]
pub struct TransactionInputBundleDesc<E>
	where E: JubjubEngine
{
	pub privkey: E::Fs,
	pub change_value: Value,
	pub inputs: Vec<TransactionInputDesc<E>>,
}

impl<E> TransactionInputBundleDesc<E>
	where E: JubjubEngine
{
	fn input_value(&self) -> Option<Value> {
		self.inputs.iter()
			.fold(Some(0u64), |sum, input| sum?.checked_add(input.value))
	}

	fn build<R, P>(
		self,
		nonce_total: E::Fs,
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E, P>>,
		params: &E::Params,
		rng: &mut R,
	)
		-> Result<UnprovenTransactionInputBundle<E>, Error>
		where
			R: RngCore + CryptoRng,
			P: Deref<Target=E::Params>,
	{
		let generator: edwards::Point<E, Unknown> =
			params.generator(FixedGenerators::ProofGenerationKey).into();
		let blinding_factor = E::Fs::random(rng);
		let pubkey_base = generator.mul(blinding_factor.into_repr(), params);
		let pubkey_raised = pubkey_base.mul(self.privkey.into_repr(), params);

		let mut nonce_output_total = nonce_total.clone();
		nonce_output_total.negate();

		let (input_nonces, output_nonces) = generate_nonces(
			self.inputs.len(), 1, nonce_output_total, rng
		);

		assert_eq!(output_nonces.len(), 1);
		let change_comm = value_commitment(self.change_value, &output_nonces[0], params);

		let value_total = self.inputs.iter()
			.fold(Some(0u64), |sum, input| sum?.checked_add(input.value))
			.and_then(|value_total| value_total.checked_sub(self.change_value))
			.ok_or(Error::Validation(validation::Error::ValueOverflow))?;

		let privkey = &self.privkey;
		let inputs = self.inputs.into_iter().zip(input_nonces.into_iter())
			.map(|(input, nonce)| input.build(nonce, privkey, &pubkey_base, merkle_tree, params))
			.collect::<Result<_, _>>()?;

		let assignment = range::Assignment {
			value: value_total,
			nonce: nonce_total,
		};

		Ok(UnprovenTransactionInputBundle {
			pubkey: (pubkey_base, pubkey_raised),
			inputs,
			change_comm: change_comm.into(),
			proof_assignment: assignment,
		})
	}
}

impl<E> TransactionDesc<E>
	where E: JubjubEngine
{
	fn check_values_balance(&self) -> Result<(), Error> {
		let mut input_total = self.inputs.iter()
			.fold(Some(0u64), |sum, bundle| sum?.checked_add(bundle.input_value()?))
			.ok_or(Error::Validation(validation::Error::ValueOverflow))?;
		let change_total = self.inputs.iter()
			.fold(Some(0u64), |sum, bundle| sum?.checked_add(bundle.change_value));
		let mut output_total = self.outputs.iter()
			.fold(change_total, |sum, output| sum?.checked_add(output.value))
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

	pub fn build<'a, BN, R, P>(
		self,
		block_number: BN,
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E, P>>,
		params: &'a <E as JubjubEngine>::Params,
		rng: &'a mut R,
	)
		-> Result<UnprovenTransaction<E, BN>, Error>
		where
			BN: BlockNumber,
			R: RngCore + CryptoRng,
			P: Deref<Target=E::Params>,
	{
		self.check_values_balance()?;

		let (input_nonces, output_nonces) = generate_nonces(
			self.inputs.len(), self.outputs.len(), E::Fs::zero(), rng
		);
		let inputs = self.inputs.into_iter().zip(input_nonces.into_iter())
			.map(|(input, nonce)| input.build(nonce, merkle_tree, params, rng))
			.collect::<Result<_, _>>()?;
		let outputs = self.outputs.into_iter().zip(output_nonces.into_iter())
			.map(|(output, nonce)| output.build(nonce, params))
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
	pub fn coin(&self, privkey: &E::Fs, params: &E::Params) -> Coin<E> {
		let pubkey_base_point = self.pubkey_base.clone();
		let pubkey_raised_point = pubkey_base_point.mul(privkey.into_repr(), params);
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
	pub inputs: Vec<UnprovenTransactionInputBundle<E>>,
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
	#[allow(dead_code)]
	fn validate_assignments<P>(
		&self,
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E, P>>,
		params: &PublicParams<E>,
	) -> Result<(), &str>
		where P: Deref<Target=E::Params>
	{
		for input in self.inputs.iter() {
			input.validate_assignments(merkle_tree, params.jubjub_params())?;
		}
		for output in self.outputs.iter() {
			let valid_credential = verify_credential(
				params.certificate_params(),
				params.authority_pubkey(),
				&output.credential
			);
			if !valid_credential {
				return Err("invalid credential on output");
			}
		}
		Ok(())
	}
}

#[derive(Clone)]
pub struct UnprovenTransactionInput<E>
	where E: JubjubEngine
{
	pub value_comm: edwards::Point<E, Unknown>,
	pub nullifier: Nullifier,
	pub proof_assignment: spend::Assignment<E>,
}

impl<E> UnprovenTransactionInput<E>
	where E: JubjubEngine
{
	fn validate_assignment<P>(
		&self,
		pubkey: &(edwards::Point<E, Unknown>, edwards::Point<E, Unknown>),
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E, P>>,
		params: &<E as JubjubEngine>::Params
	) -> Result<(), &str>
		where P: Deref<Target=E::Params>
	{
		let assigned = &self.proof_assignment;

		let value_comm_old = value_commitment(
			assigned.value, &assigned.value_nonce_old, params
		);
		let value_comm_new = value_commitment(
			assigned.value, &assigned.value_nonce_new, params
		);

		if self.value_comm != value_comm_new.into() {
			return Err("input value commitment mismatch");
		}

		let pubkey_raised_old = assigned.pubkey_base_old.mul(assigned.privkey.into_repr(), params);
		let pubkey_raised_new = assigned.pubkey_base_new.mul(assigned.privkey.into_repr(), params);

		if pubkey.0 != assigned.pubkey_base_new {
			return Err("pubkey base point mismatch");
		}
		if pubkey.1 != pubkey_raised_new {
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

		if assigned.nullifier != compute_nullifier(&assigned.privkey, assigned.position) {
			return Err("nullifier mismatch");
		}

		Ok(())
	}

	pub fn prove<R>(self, params: &PublicParams<E>, rng: &mut R)
		-> Result<TransactionInput<E>, SynthesisError>
		where R: RngCore + CryptoRng,
	{
		let circuit = spend::Circuit {
			params: params.jubjub_params(),
			merkle_depth: MERKLE_DEPTH,
			assigned: Some(self.proof_assignment),
		};
		let proof = create_random_proof(circuit, params.spend_params(), None, rng)?;
		Ok(TransactionInput {
			value_comm: self.value_comm,
			nullifier: self.nullifier,
			proof,
		})
	}
}

pub struct UnprovenTransactionOutput<E>
	where E: JubjubEngine
{
	pub value_comm: edwards::Point<E, Unknown>,
	pub credential: UserCredential<E>,
}

impl<E, BN> UnprovenTransaction<E, BN>
	where
		E: JubjubEngine,
		BN: BlockNumber,
{
	pub fn prove<R>(self, params: &PublicParams<E>, rng: &mut R)
		-> Result<Transaction<E, BN>, SynthesisError>
		where R: RngCore + CryptoRng
	{
		let inputs = self.inputs.into_iter()
			.map(|input| input.prove(params, rng))
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

impl<E> UnprovenTransactionOutput<E>
	where E: JubjubEngine
{
	pub fn prove<R>(self, params: &PublicParams<E>, rng: &mut R)
		-> Result<TransactionOutput<E>, SynthesisError>
		where R: RngCore + CryptoRng
	{
		let certificate = issue_certificate(
			rng,
			params.certificate_params(),
			params.authority_pubkey(),
			&self.credential,
		)?;
		Ok(TransactionOutput {
			value_comm: self.value_comm,
			certificate,
		})
	}
}

#[derive(Clone)]
pub struct UnprovenTransactionInputBundle<E>
	where E: JubjubEngine
{
	pub pubkey: (edwards::Point<E, Unknown>, edwards::Point<E, Unknown>),
	pub inputs: Vec<UnprovenTransactionInput<E>>,
	pub change_comm: edwards::Point<E, Unknown>,
	pub proof_assignment: range::Assignment<E>,
}

impl<E> UnprovenTransactionInputBundle<E>
	where E: JubjubEngine
{
	fn validate_assignments<P>(
		&self,
		merkle_tree: &IncrementalMerkleTree<PedersenHasher<E, P>>,
		params: &<E as JubjubEngine>::Params
	) -> Result<(), &str>
		where P: Deref<Target=E::Params>
	{
		let assigned = &self.proof_assignment;

		let assignment_comm = value_commitment(assigned.value, &assigned.nonce, params);
		let aggregate_comm = self.inputs.iter()
			.fold(self.change_comm.negate(), |sum, input| sum.add(&input.value_comm, params));
		if aggregate_comm != assignment_comm.into() {
			return Err("change commitment mismatch");
		}

		for input in self.inputs.iter() {
			input.validate_assignment(&self.pubkey, merkle_tree, params)?;
		}
		Ok(())
	}

	pub fn prove<R>(self, params: &PublicParams<E>, rng: &mut R)
		-> Result<TransactionInputBundle<E>, SynthesisError>
		where R: RngCore + CryptoRng
	{
		let inputs = self.inputs.into_iter()
			.map(|input| input.prove(params, rng))
			.collect::<Result<_, _>>()?;

		let circuit = range::Circuit {
			params: params.jubjub_params(),
			assigned: Some(self.proof_assignment),
		};
		let proof = create_random_proof(circuit, params.range_params(), None, rng)?;

		Ok(TransactionInputBundle {
			pubkey: self.pubkey,
			inputs,
			change_comm: self.change_comm,
			proof,
		})
	}
}

fn is_low_order<E>(pt: &edwards::Point<E, Unknown>, params: &E::Params) -> bool
	where E: JubjubEngine
{
	pt.mul_by_cofactor(params) == edwards::Point::zero()
}

fn generate_nonces<F, R>(n_inputs: usize, n_outputs: usize, output_total: F, rng: &mut R)
	-> (Vec<F>, Vec<F>)
	where F: Field,
		  R: RngCore + CryptoRng
{
	let mut input_nonces = (0..n_inputs)
		.map(|_| F::random(rng))
		.collect::<Vec<_>>();
	let mut output_nonces = (0..n_outputs)
		.map(|_| F::random(rng))
		.collect::<Vec<_>>();

	let mut actual_output_total = F::zero();
	for nonce in input_nonces.iter() {
		actual_output_total.sub_assign(nonce);
	}
	for nonce in output_nonces.iter() {
		actual_output_total.add_assign(nonce);
	}

	let mut output_delta = output_total;
	output_delta.sub_assign(&actual_output_total);

	if output_delta != F::zero() {
		match (input_nonces.first_mut(), output_nonces.first_mut()) {
			(Some(nonce), _) => nonce.sub_assign(&output_delta),
			(_, Some(nonce)) => nonce.add_assign(&output_delta),
			_ => panic!("generate_nonces called with 0 inputs, 0 outputs, and non-zero total"),
		}
	}

	(input_nonces, output_nonces)
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::validation::{self, check_transaction};

	use crate::test_support::{
		Harness, MockChainState,
		TransactionValues, TransactionInputBundleValues,
		add_transaction_inputs, random_transaction_desc,
	};

	#[test]
	fn build_empty_transaction() {
		let mut t = Harness::with_fixed_rng();

		let tx_values = TransactionValues {
			input_values: vec![],
			output_values: vec![],
			issuance: 0,
		};
		let tx_desc = random_transaction_desc(
			t.merkle_tree.size(), &t.credential, tx_values, &*t.jubjub_params, &mut t.rng
		);

		let tx = tx_desc.build(
			t.block_number,
			&t.merkle_tree,
			&*t.jubjub_params,
			&mut t.rng
		).unwrap();

		tx.validate_assignments(&t.merkle_tree, &t.params).unwrap();
		assert!(tx.inputs.is_empty());
		assert!(tx.outputs.is_empty());
		assert_eq!(tx.issuance, 0);
		assert_eq!(tx.accumulator_state_block_number, t.block_number);
	}

	#[test]
	fn build_transaction_with_inputs_and_outputs() {
		let mut t = Harness::with_fixed_rng();

		let tx_values = TransactionValues {
			input_values: vec![
				TransactionInputBundleValues {
					change_value: 0,
					input_values: vec![100_000, 200_000],
				},
			],
			output_values: vec![300_000, 400_000],
			issuance: 400_000,
		};
		let tx_desc = random_transaction_desc(
			t.merkle_tree.size(), &t.credential, tx_values, &*t.jubjub_params, &mut t.rng
		);

		add_transaction_inputs(&mut t.merkle_tree, &tx_desc, &*t.jubjub_params);

		let tx = tx_desc.build(
			t.block_number,
			&t.merkle_tree,
			&*t.jubjub_params,
			&mut t.rng
		).unwrap();

		tx.validate_assignments(&t.merkle_tree, &t.params).unwrap();
		assert_eq!(tx.inputs.len(), 1);
		assert_eq!(tx.inputs[0].inputs.len(), 2);
		assert_eq!(tx.outputs.len(), 2);
		assert_eq!(tx.issuance, 400_000);
		assert_eq!(tx.accumulator_state_block_number, t.block_number);
	}

	#[test]
	fn build_transaction_with_inputs_and_no_outputs() {
		let mut t = Harness::with_fixed_rng();

		let tx_values = TransactionValues {
			input_values: vec![
				TransactionInputBundleValues {
					change_value: 0,
					input_values: vec![100_000, 200_000],
				},
			],
			output_values: vec![],
			issuance: -300_000,
		};
		let tx_desc = random_transaction_desc(
			t.merkle_tree.size(), &t.credential, tx_values, &*t.jubjub_params, &mut t.rng
		);

		add_transaction_inputs(&mut t.merkle_tree, &tx_desc, &*t.jubjub_params);

		let tx = tx_desc.build(
			t.block_number,
			&t.merkle_tree,
			&*t.jubjub_params,
			&mut t.rng
		).unwrap();

		tx.validate_assignments(&t.merkle_tree, &t.params).unwrap();
		assert_eq!(tx.inputs.len(), 1);
		assert_eq!(tx.inputs[0].inputs.len(), 2);
		assert_eq!(tx.outputs.len(), 0);
		assert_eq!(tx.issuance, -300_000);
		assert_eq!(tx.accumulator_state_block_number, t.block_number);
	}

	#[test]
	fn build_transaction_with_outputs_and_no_inputs() {
		let mut t = Harness::with_fixed_rng();

		let tx_values = TransactionValues {
			input_values: vec![],
			output_values: vec![300_000, 400_000],
			issuance: 700_000,
		};
		let tx_desc = random_transaction_desc(
			t.merkle_tree.size(), &t.credential, tx_values, &*t.jubjub_params, &mut t.rng
		);

		let tx = tx_desc.build(
			t.block_number,
			&t.merkle_tree,
			&*t.jubjub_params,
			&mut t.rng
		).unwrap();

		tx.validate_assignments(&t.merkle_tree, &t.params).unwrap();
		assert_eq!(tx.inputs.len(), 0);
		assert_eq!(tx.outputs.len(), 2);
		assert_eq!(tx.issuance, 700_000);
		assert_eq!(tx.accumulator_state_block_number, t.block_number);
	}

	#[test]
	fn build_transaction_with_overflow() {
		let mut t = Harness::with_fixed_rng();

		let tx_values = TransactionValues {
			input_values: vec![
				TransactionInputBundleValues {
					change_value: 0,
					input_values: vec![std::u64::MAX, std::u64::MAX],
				},
			],
			output_values: vec![std::u64::MAX, std::u64::MAX],
			issuance: 0,
		};
		let tx_desc = random_transaction_desc(
			t.merkle_tree.size(), &t.credential, tx_values, &*t.jubjub_params, &mut t.rng
		);

		add_transaction_inputs(&mut t.merkle_tree, &tx_desc, &*t.jubjub_params);

		let err = tx_desc.build(
			t.block_number,
			&t.merkle_tree,
			&*t.jubjub_params,
			&mut t.rng
		).err().unwrap();

		assert_eq!(err, Error::Validation(validation::Error::ValueOverflow));
	}

	#[test]
	fn build_unbalanced_transaction() {
		let mut t = Harness::with_fixed_rng();

		let tx_values = TransactionValues {
			input_values: vec![
				TransactionInputBundleValues {
					change_value: 0,
					input_values: vec![100_000],
				},
			],
			output_values: vec![200_000],
			issuance: 0,
		};
		let tx_desc = random_transaction_desc(
			t.merkle_tree.size(), &t.credential, tx_values, &*t.jubjub_params, &mut t.rng
		);

		let err = tx_desc.build(
			t.block_number,
			&t.merkle_tree,
			&*t.jubjub_params,
			&mut t.rng
		).err().unwrap();

		assert_eq!(err, Error::Validation(validation::Error::UnbalancedTransaction));
	}

	#[test]
	fn transaction_with_real_proofs() {
		let mut t = Harness::with_fixed_rng();

		let tx_values = TransactionValues {
			input_values: vec![
				TransactionInputBundleValues {
					change_value: 100_000,
					input_values: vec![100_000, 200_000],
				},
			],
			output_values: vec![300_000, 400_000],
			issuance: 500_000,
		};
		let tx_desc = random_transaction_desc(
			t.merkle_tree.size(), &t.credential, tx_values, &*t.jubjub_params, &mut t.rng
		);

		add_transaction_inputs(&mut t.merkle_tree, &tx_desc, &*t.jubjub_params);

		let unproven_tx = tx_desc.build(
			t.block_number,
			&t.merkle_tree,
			&*t.jubjub_params,
			&mut t.rng
		).unwrap();
		// unproven_tx.validate_assignments(&t.merkle_tree, &t.params).unwrap();

		let tx = unproven_tx.prove(&t.params, &mut t.rng).unwrap();

		let chain_state = MockChainState::new(
			vec![(t.block_number, t.merkle_tree.root())],
			vec![],
		);
		let res = check_transaction(&t.params, &tx, &chain_state);
		if let Err(ref err) = res {
			println!("validation error {}", err);
		}
		assert!(res.is_ok());
	}
}
