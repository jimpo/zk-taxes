use crate::certificate::{
	AuthorityKey, PublicParams as CertificateParams, UserCredential, UserKey,
	gen_authority_key, gen_user_key, issue_credential,
};
use crate::constants::MERKLE_DEPTH;
use crate::hasher::PedersenHasher;
use crate::merkle_tree::IncrementalMerkleTree;
use crate::proofs;
use crate::wallet::{TransactionDesc, TransactionInputDesc, TransactionInputBundleDesc};
use crate::validation::PublicParams;

use pairing::bls12_381::Bls12;
use rand::{CryptoRng, RngCore, SeedableRng, rngs::StdRng};
use std::ops::Deref;
use std::rc::Rc;
use zcash_primitives::jubjub::{JubjubBls12, JubjubEngine};

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
