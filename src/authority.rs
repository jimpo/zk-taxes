/// Operations performed by the tax authority.

use crate::certificate::{AuthorityKey, UserID, trace_certificate};
use crate::primitives::Transaction;
use crate::validation::PublicParams;

use std::collections::HashMap;
use zcash_primitives::jubjub::{edwards, JubjubEngine, Unknown};

/// Determine commitments to aggregate income by user ID over a sequence of transactions.
pub fn aggregate_incomes<'a, E, BN, I>(
	params: &PublicParams<E>,
	tracing_key: &AuthorityKey<E>,
	transactions: I,
) -> HashMap<UserID<E>, edwards::Point<E, Unknown>>
	where
		E: JubjubEngine,
		BN: 'a,
		I: Iterator<Item=&'a Transaction<E, BN>>,
{
	let mut incomes = HashMap::new();
	for transaction in transactions {
		for output in transaction.outputs.iter() {
			let	id = trace_certificate(
				params.certificate_params(),
				tracing_key,
				&output.certificate
			);
			let income = incomes.entry(id).or_insert_with(edwards::Point::zero);
			*income = income.add(&output.value_comm, params.jubjub_params());
		}
	}
	incomes
}