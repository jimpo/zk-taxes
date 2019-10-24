use bellman::groth16;
use ff::PrimeField;
use std::cmp;
use std::fmt::{self, Display, Formatter};
use std::rc::Rc;
use zcash_primitives::jubjub::{edwards, FixedGenerators, JubjubEngine, JubjubParams, Unknown};

use crate::certificate;
use crate::transaction::{
	BlockNumber, Nullifier, Transaction, TransactionInputBundle, TransactionInput,
};

#[derive(Debug, PartialEq)]
pub enum Error {
	ValueOverflow,
	UnbalancedTransaction,
	InvalidBlockNumber,
	InvalidAccumulatorState,
	DoubleSpend(usize),
	ProofSynthesis(String),
	InvalidCertificate { output_index: usize },
	InvalidRangeProof { bundle_index: usize },
	InvalidSpendProof { bundle_index: usize, input_index: usize }
}

impl Display for Error {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		match self {
			Error::ValueOverflow => write!(f, "transaction value amounts overflow u64"),
			Error::UnbalancedTransaction =>
				write!(f, "difference between transaction input and output sum does not match issuance"),
			Error::InvalidBlockNumber =>
				write!(f, "no accumulator state for given block number"),
			Error::InvalidAccumulatorState =>
				write!(f, "accumulator state is not a valid Merkle root"),
			Error::DoubleSpend(index) =>
				write!(f, "input at index {} is already spent", index),
			Error::ProofSynthesis(reason) =>
				write!(f, "unexpected bellman error verifying proof: {}", reason),
			Error::InvalidCertificate { output_index } =>
				write!(f, "traceable anonymous certificate on output {} is invalid", output_index),
			Error::InvalidRangeProof { bundle_index } =>
				write!(f, "range proof on input bundle {} is invalid", bundle_index),
			Error::InvalidSpendProof { bundle_index, input_index } =>
				write!(
					f,
					"spend proof on input {} of bundle {} is invalid",
					input_index, bundle_index,
				),
		}
	}
}

impl std::error::Error for Error {}

pub type AccumulatorState<E: JubjubEngine> = <E::Fr as PrimeField>::Repr;

pub trait ChainState<E>
	where E: JubjubEngine,
{
	type BlockNumber: BlockNumber;

	fn accumulator_state_at_height(&self, block_number: &Self::BlockNumber)
		-> Option<AccumulatorState<E>>;
	fn nullifier_exists(&self, nullifier: Nullifier) -> bool;
}

pub struct PublicParams<E>
	where E: JubjubEngine
{
	jubjub_params: Rc<E::Params>,
	certificate_params: certificate::PublicParams<E>,
	range_proof_params: groth16::Parameters<E>,
	range_verifying_key: groth16::PreparedVerifyingKey<E>,
	spend_proof_params: groth16::Parameters<E>,
	spend_verifying_key: groth16::PreparedVerifyingKey<E>,
}

impl<E> PublicParams<E>
	where E: JubjubEngine
{
	pub fn new(
		jubjub_params: Rc<E::Params>,
		certificate_proof_params: groth16::Parameters<E>,
		range_proof_params: groth16::Parameters<E>,
		spend_proof_params: groth16::Parameters<E>,
	) -> Self
	{
		let certificate_params = certificate::PublicParams::new(
			jubjub_params.clone(),
			certificate_proof_params,
		);
		let range_verifying_key = groth16::prepare_verifying_key(&range_proof_params.vk);
		let spend_verifying_key = groth16::prepare_verifying_key(&spend_proof_params.vk);
		PublicParams {
			jubjub_params,
			certificate_params,
			range_proof_params,
			range_verifying_key,
			spend_proof_params,
			spend_verifying_key,
		}
	}

	pub fn jubjub_params(&self) -> &E::Params {
		self.jubjub_params.as_ref()
	}

	pub fn range_params(&self) -> &groth16::Parameters<E> {
		&self.range_proof_params
	}

	pub fn spend_params(&self) -> &groth16::Parameters<E> {
		&self.spend_proof_params
	}

	pub fn certificate_params(&self) -> &certificate::PublicParams<E> {
		&self.certificate_params
	}
}

pub fn check_transaction<E, CS, BN>(
	params: &PublicParams<E>,
	transaction: &Transaction<E, BN>,
	chain_state: &CS,
) -> Result<(), Error>
	where
		E: JubjubEngine,
		CS: ChainState<E, BlockNumber=BN>,
		BN: BlockNumber,
{
	let accumulator_state =
		chain_state.accumulator_state_at_height(&transaction.accumulator_state_block_number)
			.ok_or(Error::InvalidBlockNumber)?;

	for (bundle_index, bundle) in transaction.inputs.iter().enumerate() {
		check_bundle_range_proof(params, bundle_index, bundle)?;
		for (input_index, input) in bundle.inputs.iter().enumerate() {
			check_input_spend_proof(
				params, accumulator_state, bundle_index, bundle, input_index, input
			)?;
		}
	}

	let input_commitments = transaction.inputs.iter()
		.flat_map(|bundle| bundle.inputs.iter())
		.map(|input| input.value_comm.clone());
	let change_commitments = transaction.inputs.iter()
		.map(|bundle| bundle.change_comm.negate());
	let output_commitments = transaction.outputs.iter()
		.map(|output| output.value_comm.negate());
	let value_commitments = input_commitments.chain(output_commitments);

	// Check that input and output commitments sum to 0.
	//
	// We can perform operators in the full group of curve points (not the prime order subgroup)
	// because the prime order is checked inside of the input and output SNARKs.
	let zero = edwards::Point::<E, Unknown>::zero();
	let issuance_commitment = if transaction.issuance == 0 {
		zero.clone()
	} else {
		let mut comm = params.jubjub_params.generator(FixedGenerators::ValueCommitmentValue)
			.mul(transaction.issuance.abs() as u64, params.jubjub_params());
		if transaction.issuance.is_negative() {
			comm = comm.negate();
		}
		comm.into()
	};

	let commitment_sum = value_commitments.fold(
		issuance_commitment,
		|sum, comm| sum.add(&comm, params.jubjub_params())
	);

	if commitment_sum != zero {
		return Err(Error::UnbalancedTransaction);
	}

	// TODO: Check output credentials


	// Check that nullifiers are valid.
	let mut nullifiers = transaction.inputs.iter()
		.flat_map(|bundle| bundle.inputs.iter())
		.map(|input| input.nullifier)
		.enumerate()
		.collect::<Vec<_>>();

	// Check that there are no duplicates within the transaction.
	nullifiers.sort_unstable();
	for i in 1..nullifiers.len() {
		if nullifiers[i-1].1 == nullifiers[i].1 {
			let index = cmp::max(nullifiers[i-1].0, nullifiers[i-1].0);
			return Err(Error::DoubleSpend(index));
		}
	}

	// Check that all nullifiers are unused.
	match nullifiers.iter().find(|(_, nullifier)| chain_state.nullifier_exists(*nullifier)) {
		Some((index, _)) => return Err(Error::DoubleSpend(*index)),
		None => {}
	}

	Ok(())
}

fn check_bundle_range_proof<E>(
	params: &PublicParams<E>,
	bundle_index: usize,
	bundle: &TransactionInputBundle<E>,
) -> Result<(), Error>
	where E: JubjubEngine
{
	let (change_comm_x, change_comm_y) = bundle.change_comm.to_xy();
	let valid = groth16::verify_proof(
		&params.range_verifying_key,
		&bundle.proof,
		&[change_comm_x, change_comm_y][..],
	)
		.map_err(|err| Error::ProofSynthesis(err.to_string()))?;
	if valid {
		Ok(())
	} else {
		Err(Error::InvalidRangeProof { bundle_index })
	}
}

fn check_input_spend_proof<E>(
	params: &PublicParams<E>,
	accumulator_state: AccumulatorState<E>,
	bundle_index: usize,
	bundle: &TransactionInputBundle<E>,
	input_index: usize,
	input: &TransactionInput<E>,
) -> Result<(), Error>
	where E: JubjubEngine
{
	let anchor = E::Fr::from_repr(accumulator_state)
		.map_err(|_| Error::InvalidAccumulatorState)?;
	let (value_comm_x, value_comm_y) = input.value_comm.to_xy();
	let (pubkey_base_x, pubkey_base_y) = bundle.pubkey.0.to_xy();
	let (pubkey_raised_x, pubkey_raised_y) = bundle.pubkey.1.to_xy();
	let valid = groth16::verify_proof(
		&params.spend_verifying_key,
		&input.proof,
		&[
			anchor,
			value_comm_x, value_comm_y,
			pubkey_base_x, pubkey_base_y,
			pubkey_raised_x, pubkey_raised_y,
			// TODO: nullifier
		][..],
	)
		.map_err(|err| Error::ProofSynthesis(err.to_string()))?;
	if valid {
		Ok(())
	} else {
		Err(Error::InvalidSpendProof { bundle_index, input_index })
	}
}
