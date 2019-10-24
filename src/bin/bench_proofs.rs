use zk_taxes::{
	constants::MERKLE_DEPTH,
	hasher::PedersenHasher,
	merkle_tree::IncrementalMerkleTree,
	proofs::tests::{range_params, spend_params},
	transaction::BlockNumber,
	wallet::{
		TransactionDesc, TransactionInputDesc, TransactionInputBundleDesc, TransactionOutputDesc,
		UnprovenTransaction,
	},
};

use ff::Field;
use pairing::bls12_381::Bls12;
use rand::{thread_rng, RngCore};
use std::time::{Duration, Instant};
use zcash_primitives::jubjub::{FixedGenerators, JubjubBls12, JubjubEngine, JubjubParams};

fn add_input<E>(
	merkle_tree: &mut IncrementalMerkleTree<PedersenHasher<E>>,
	input: &TransactionInputDesc<E>,
	privkey: &E::Fs,
	params: &E::Params,
)
	where E: JubjubEngine
{
	let mut encoded_coin = Vec::new();
	input.coin(privkey, params).write(&mut encoded_coin).unwrap();

	merkle_tree.track_next_leaf();
	merkle_tree.push_data(&encoded_coin);
}

fn add_bundle_inputs<E>(
	merkle_tree: &mut IncrementalMerkleTree<PedersenHasher<E>>,
	bundle_desc: &TransactionInputBundleDesc<E>,
	params: &E::Params,
)
	where E: JubjubEngine
{
	for input_desc in bundle_desc.inputs.iter() {
		add_input(merkle_tree, input_desc, &bundle_desc.privkey, params);
	}
}

fn add_transaction_inputs<E>(
	merkle_tree: &mut IncrementalMerkleTree<PedersenHasher<E>>,
	tx_desc: &TransactionDesc<E>,
	params: &E::Params,
)
	where E: JubjubEngine
{
	for bundle_desc in tx_desc.inputs.iter() {
		add_bundle_inputs(merkle_tree, bundle_desc, &params);
	}
}

fn build_unproven_transaction<BN, R>(
	block_number: BN,
	merkle_tree: &mut IncrementalMerkleTree<PedersenHasher<Bls12>>,
	params: &<Bls12 as JubjubEngine>::Params,
	rng: &mut R,
)
	-> UnprovenTransaction<Bls12, BN>
	where
		BN: BlockNumber,
		R: RngCore,
{
	let tx_desc = TransactionDesc::<Bls12> {
		inputs: vec![
			TransactionInputBundleDesc {
				privkey: <Bls12 as JubjubEngine>::Fs::one(),
				change_value: 0,
				inputs: vec![
					TransactionInputDesc {
						position: 0,
						value: 100_000,
						value_nonce: <Bls12 as JubjubEngine>::Fs::zero(),
						pubkey_base: params.generator(FixedGenerators::SpendingKeyGenerator).into(),
					},
				],
			},
		],
		outputs: vec![
			TransactionOutputDesc {
				value: 100_000,
			},
		],
		issuance: 0,
	};

	add_transaction_inputs(merkle_tree, &tx_desc, params);

	let tx = tx_desc.build(
		block_number,
		merkle_tree,
		params,
		rng,
	).unwrap();

	tx
}

fn main() {
	let params = JubjubBls12::new();
	let mut rng = thread_rng();
	let block_number = 42;
	let mut merkle_tree = IncrementalMerkleTree::empty(
		MERKLE_DEPTH, PedersenHasher::new(&params)
	);

	let unproven_tx = build_unproven_transaction(
		block_number,
		&mut merkle_tree,
		&params,
		&mut rng,
	);

	let range_proof_params = range_params().unwrap();
	let spend_proof_params = spend_params().unwrap();

	const SAMPLES: u32 = 1;

	let mut total_time = Duration::new(0, 0);
	for _ in 0..SAMPLES {
		let input = unproven_tx.inputs[0].clone();
		let start = Instant::now();
		let _ = input.prove(&params, &range_proof_params, &spend_proof_params, &mut rng).unwrap();
		total_time += start.elapsed();
	}
	let avg = total_time / SAMPLES;
	let avg = avg.subsec_nanos() as f64 / 1_000_000_000f64 + (avg.as_secs() as f64);

	println!("Average proving time (in seconds): {}", avg);
}