use ff::PrimeField;
use std::cmp;
use std::fmt::{self, Display, Formatter};
use zcash_primitives::jubjub::{edwards, FixedGenerators, JubjubEngine, JubjubParams, Unknown};

use crate::transaction::{BlockNumber, Nullifier, Transaction};

#[derive(Debug, PartialEq)]
pub enum Error<BN>
	where BN: BlockNumber,
{
	ValueOverflow,
	UnbalancedTransaction,
	InvalidBlockNumber(BN),
	DoubleSpend(usize),
}

impl<BN> Display for Error<BN>
	where BN: BlockNumber
{
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		match self {
			Error::ValueOverflow => write!(f, "transaction value amounts overflow u64"),
			Error::UnbalancedTransaction =>
				write!(f, "difference between transaction input and output sum does not match issuance"),
			Error::InvalidBlockNumber(block_number) =>
				write!(f, "no accumulator state for block number {}", block_number),
			Error::DoubleSpend(index) =>
				write!(f, "input at index {} is already spent", index),
		}
	}
}

impl<BN> std::error::Error for Error<BN>
	where BN: BlockNumber
{}

pub type AccumulatorState<E: JubjubEngine> = <E::Fr as PrimeField>::Repr;

pub trait ChainState<E>
	where E: JubjubEngine,
{
	type BlockNumber: BlockNumber;

	fn accumulator_state_at_height(&self, block_number: &Self::BlockNumber)
		-> Option<AccumulatorState<E>>;
	fn nullifier_exists(&self, nullifier: Nullifier) -> bool;
}

pub fn check_transaction<E, CS, BN>(
	params: &E::Params,
	transaction: &Transaction<E, BN>,
	chain_state: &CS,
) -> Result<(), Error<BN>>
	where
		E: JubjubEngine,
		CS: ChainState<E, BlockNumber=BN>,
		BN: BlockNumber,
{
	let accumulator_state =
		chain_state.accumulator_state_at_height(&transaction.accumulator_state_block_number)
			.ok_or_else(|| {
				Error::InvalidBlockNumber(transaction.accumulator_state_block_number.clone())
			})?;

	// TODO: Check input proof
	// TODO: Check ciphertext proof

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
		let mut comm = params.generator(FixedGenerators::ValueCommitmentValue)
			.mul(transaction.issuance.abs() as u64, &params);
		if transaction.issuance.is_negative() {
			comm = comm.negate();
		}
		comm.into()
	};

	let commitment_sum = value_commitments.fold(
		issuance_commitment,
		|sum, comm| sum.add(&comm, &params)
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
