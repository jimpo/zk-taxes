use zk_taxes::{
	test_support::{Harness, add_transaction_inputs},
	wallet::{
		TransactionDesc, TransactionInputDesc, TransactionInputBundleDesc, TransactionOutputDesc,
		UnprovenTransaction,
	},
};

use ff::Field;
use pairing::bls12_381::Bls12;
use rand::{CryptoRng, RngCore, thread_rng};
use std::time::{Duration, Instant};
use zcash_primitives::jubjub::{FixedGenerators, JubjubEngine, JubjubParams};

fn build_unproven_transaction<R>(t: &mut Harness<R>, tx_desc: &TransactionDesc<Bls12>)
	-> UnprovenTransaction<Bls12, u64>
	where
		R: RngCore + CryptoRng,
{
	add_transaction_inputs(&mut t.merkle_tree, tx_desc, &*t.jubjub_params);

	tx_desc
		.clone()
		.build(
			t.block_number,
			&t.merkle_tree,
			&*t.jubjub_params,
			&mut t.rng,
		)
		.unwrap()
}

fn main() {
	let mut t = Harness::new(thread_rng());

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
						pubkey_base: t.jubjub_params
							.generator(FixedGenerators::SpendingKeyGenerator).into(),
					},
				],
			},
		],
		outputs: vec![
			TransactionOutputDesc {
				value: 100_000,
				credential: t.credential.clone(),
			},
		],
		issuance: 0,
	};
	let unproven_tx = build_unproven_transaction(&mut t, &tx_desc);

	const SAMPLES: u32 = 1;

	let mut total_time = Duration::new(0, 0);
	for _ in 0..SAMPLES {
		let input = unproven_tx.inputs[0].clone();
		let start = Instant::now();
		let _ = input.prove(&t.params, &mut t.rng).unwrap();
		total_time += start.elapsed();
	}
	let avg = total_time / SAMPLES;
	let avg = avg.subsec_nanos() as f64 / 1_000_000_000f64 + (avg.as_secs() as f64);

	println!("Average proving time (in seconds): {}", avg);
}