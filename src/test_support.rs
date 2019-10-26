use crate::certificate::{
	AuthorityKey, PublicParams as CertificateParams, UserCredential, UserKey,
	gen_authority_key, gen_user_key, issue_credential,
};
use crate::constants::MERKLE_DEPTH;
use crate::hasher::PedersenHasher;
use crate::merkle_tree::IncrementalMerkleTree;
use crate::proofs;
use crate::transaction::{BlockNumber, Nullifier, Value};
use crate::wallet::{
	TransactionDesc, TransactionInputDesc, TransactionInputBundleDesc, TransactionOutputDesc,
};
use crate::validation::{AccumulatorState, ChainState, PublicParams};

use ff::Field;
use pairing::bls12_381::Bls12;
use rand::{CryptoRng, RngCore, SeedableRng, rngs::StdRng};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::ops::Deref;
use std::rc::Rc;
use zcash_primitives::jubjub::{FixedGenerators, JubjubBls12, JubjubEngine, JubjubParams};

pub struct Harness<R>
	where R: RngCore + CryptoRng
{
	pub rng: R,
	pub jubjub_params: Rc<JubjubBls12>,
	pub authority_key: AuthorityKey<Bls12>,
	pub params: PublicParams<Bls12>,
	pub block_number: u64,
	pub merkle_tree: IncrementalMerkleTree<PedersenHasher<Bls12, Rc<JubjubBls12>>>,
	pub user_key: UserKey<Bls12>,
	pub credential: UserCredential<Bls12>,
}

impl<R> Harness<R>
	where R: RngCore + CryptoRng
{
	pub fn new(mut rng: R) -> Self {
		let jubjub_params = Rc::new(JubjubBls12::new());
		let authority_key = {
			let certificate_params = CertificateParams::new(
				jubjub_params.clone(),
				proofs::tests::certificate_params().unwrap(),
			);
			gen_authority_key(&mut rng, &certificate_params)
		};
		let params = PublicParams::new(
			jubjub_params.clone(),
			authority_key.pubkey().clone(),
			proofs::tests::certificate_params().unwrap(),
			proofs::tests::range_params().unwrap(),
			proofs::tests::spend_params().unwrap(),
		);
		let block_number = 42;
		let merkle_tree = IncrementalMerkleTree::empty(
			MERKLE_DEPTH, PedersenHasher::new(jubjub_params.clone())
		);
		let user_key = gen_user_key(&mut rng, params.certificate_params());
		let credential = issue_credential(
			&mut rng,
			params.certificate_params(),
			&authority_key,
			user_key.id(),
		).unwrap();
		Harness {
			jubjub_params,
			rng,
			authority_key,
			params,
			block_number,
			merkle_tree,
			user_key,
			credential,
		}
	}
}

impl Harness<StdRng> {
	pub fn with_fixed_rng() -> Self {
		Self::new(StdRng::seed_from_u64(0))
	}
}

pub fn add_input<E, P>(
	merkle_tree: &mut IncrementalMerkleTree<PedersenHasher<E, P>>,
	input: &TransactionInputDesc<E>,
	privkey: &E::Fs,
	params: &E::Params,
)
	where
		E: JubjubEngine,
		P: Deref<Target=E::Params>,
{
	let mut encoded_coin = Vec::new();
	input.coin(privkey, params).write(&mut encoded_coin).unwrap();

	merkle_tree.track_next_leaf();
	merkle_tree.push_data(&encoded_coin);
}

pub fn add_bundle_inputs<E, P>(
	merkle_tree: &mut IncrementalMerkleTree<PedersenHasher<E, P>>,
	bundle_desc: &TransactionInputBundleDesc<E>,
	params: &E::Params,
)
	where
		E: JubjubEngine,
		P: Deref<Target=E::Params>,
{
	for input_desc in bundle_desc.inputs.iter() {
		add_input(merkle_tree, input_desc, &bundle_desc.privkey, params);
	}
}

pub fn add_transaction_inputs<E, P>(
	merkle_tree: &mut IncrementalMerkleTree<PedersenHasher<E, P>>,
	tx_desc: &TransactionDesc<E>,
	params: &E::Params,
)
	where
		E: JubjubEngine,
		P: Deref<Target=E::Params>,
{
	for bundle_desc in tx_desc.inputs.iter() {
		add_bundle_inputs(merkle_tree, bundle_desc, params);
	}
}

pub struct TransactionValues {
	pub input_values: Vec<TransactionInputBundleValues>,
	pub output_values: Vec<Value>,
	pub issuance: i64,
}

pub struct TransactionInputBundleValues {
	pub input_values: Vec<Value>,
	pub change_value: Value,
}

pub fn random_transaction_desc<E, R>(
	start_position: u64,
	credential: &UserCredential<E>,
	transaction_values: TransactionValues,
	params: &E::Params,
	rng: &mut R,
) -> TransactionDesc<E>
	where
		E: JubjubEngine,
		R: RngCore,
{
	let mut position = start_position;
	let generator = params.generator(FixedGenerators::SpendingKeyGenerator);

	let input_bundles = transaction_values.input_values
		.into_iter()
		.map(|bundle_values| {
			let privkey = E::Fs::random(rng);
			let inputs = bundle_values.input_values
				.into_iter()
				.map(|input_value| {
					let input_position = position;
					position += 1;
					TransactionInputDesc {
						position: input_position,
						value: input_value,
						value_nonce: E::Fs::random(rng),
						pubkey_base: generator.mul(E::Fs::random(rng), params).into(),
					}
				})
				.collect::<Vec<_>>();
			TransactionInputBundleDesc {
				privkey,
				change_value: bundle_values.change_value,
				inputs,
			}
		})
		.collect::<Vec<_>>();
	let outputs = transaction_values.output_values
		.into_iter()
		.map(|output_value| {
			TransactionOutputDesc {
				value: output_value,
				credential: credential.clone(),
			}
		})
		.collect::<Vec<_>>();
	TransactionDesc {
		inputs: input_bundles,
		outputs,
		issuance: transaction_values.issuance,
	}
}

pub struct MockChainState<AS, BN>
	where
		BN: BlockNumber + Hash,
{
	accumulator_states: HashMap<BN, AS>,
	nullifier_set: HashSet<Nullifier>,
}

impl<AS, BN> MockChainState<AS, BN>
	where
		BN: BlockNumber + Hash,
{
	pub fn new<ASI, NI>(accumulator_state_iter: ASI, nullifier_set_iter: NI) -> Self
		where
			ASI: IntoIterator<Item=(BN, AS)>,
			NI: IntoIterator<Item=Nullifier>,
	{
		MockChainState {
			accumulator_states: accumulator_state_iter.into_iter().collect(),
			nullifier_set: nullifier_set_iter.into_iter().collect(),
		}
	}
}

impl<E, BN> ChainState<E> for MockChainState<AccumulatorState<E>, BN>
	where
		E: JubjubEngine,
		BN: BlockNumber + Hash,
{
	type BlockNumber = BN;

	fn accumulator_state_at_height(&self, block_number: &BN) -> Option<AccumulatorState<E>> {
		self.accumulator_states.get(block_number).cloned()
	}

	fn nullifier_exists(&self, nullifier: &Nullifier) -> bool {
		self.nullifier_set.contains(nullifier)
	}
}
