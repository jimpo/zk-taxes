use bellman::{gadgets::multipack, groth16};
use bencher::{Bencher, benchmark_main, benchmark_group};
use ff::{Field, PrimeField};
use rand::{Rng, RngCore, thread_rng};
use zk_taxes::{
	certificate::{
		issue_certificate, issue_credential, trace_certificate, verify_certificate, verify_credential,
		test_support::Harness as CertificateHarness
	},
	hasher::PedersenHasher,
	merkle_tree::IncrementalMerkleTree,
	primitives::{Coin, Value, compute_nullifier, value_commitment, MERKLE_DEPTH},
	proofs::range::{Assignment as RangeAssignment, Circuit as RangeCircuit},
	proofs::spend::{Assignment as SpendAssignment, Circuit as SpendCircuit},
	proofs::tests::{range_params, spend_params},
};
use zcash_primitives::jubjub::{
	edwards, FixedGenerators, JubjubBls12, JubjubEngine, JubjubParams, Unknown,
};

fn bench_issue_credential(b: &mut Bencher) {
	let mut t = CertificateHarness::new(thread_rng());

	b.iter(|| {
		issue_credential(&mut t.rng, &t.params, &t.authority_key, t.user_key.id())
			.unwrap();
	});
}

fn bench_verify_credential(b: &mut Bencher) {
	let mut t = CertificateHarness::new(thread_rng());
	let credential = issue_credential(&mut t.rng, &t.params, &t.authority_key, t.user_key.id())
		.unwrap();

	b.iter(|| {
		assert!(verify_credential(&t.params, t.authority_key.pubkey(), &credential));
	});
}

fn bench_issue_certificate(b: &mut Bencher) {
	let mut t = CertificateHarness::new(thread_rng());
	let credential = issue_credential(&mut t.rng, &t.params, &t.authority_key, t.user_key.id())
		.unwrap();

	b.iter(|| {
		issue_certificate(&mut t.rng, &t.params, t.authority_key.pubkey(), &credential)
			.unwrap();
	});
}

fn bench_verify_certificate(b: &mut Bencher) {
	let mut t = CertificateHarness::new(thread_rng());
	let credential = issue_credential(&mut t.rng, &t.params, &t.authority_key, t.user_key.id())
		.unwrap();
	let certificate = issue_certificate(
		&mut t.rng, &t.params, t.authority_key.pubkey(), &credential
	).unwrap();

	b.iter(|| {
		assert!(verify_certificate(&t.params, t.authority_key.pubkey(), &certificate).unwrap());
	});
}

fn bench_trace_certificate(b: &mut Bencher) {
	let mut t = CertificateHarness::new(thread_rng());
	let credential = issue_credential(&mut t.rng, &t.params, &t.authority_key, t.user_key.id())
		.unwrap();
	let certificate = issue_certificate(
		&mut t.rng, &t.params, t.authority_key.pubkey(), &credential
	).unwrap();

	b.iter(|| {
		let traced_id = trace_certificate(&t.params, &t.authority_key, &certificate);
		assert_eq!(traced_id, t.user_key.id());
	});
}

fn bench_generate_range_proof(b: &mut Bencher) {
	let jubjub_params = JubjubBls12::new();
	let mut rng = thread_rng();
	let (circuit, _) = random_range_proof_instance(&jubjub_params, &mut rng);

	let proof_params = range_params().unwrap();

	b.iter(|| {
		groth16::create_random_proof(circuit.clone(), &proof_params, None, &mut rng)
			.unwrap();
	});
}

fn bench_verify_range_proof(b: &mut Bencher) {
	let jubjub_params = JubjubBls12::new();
	let mut rng = thread_rng();
	let (circuit, public_inputs) = random_range_proof_instance(&jubjub_params, &mut rng);

	let proof_params = range_params().unwrap();
	let proof = groth16::create_random_proof(circuit, &proof_params, None, &mut rng)
		.unwrap();

	let verifying_key = groth16::prepare_verifying_key(&proof_params.vk);

	b.iter(|| {
		assert!(groth16::verify_proof(&verifying_key, &proof, &public_inputs[..]).unwrap());
	});
}

fn bench_generate_spend_proof(b: &mut Bencher) {
	let jubjub_params = JubjubBls12::new();
	let mut rng = thread_rng();
	let (circuit, _) = random_spend_proof_instance(&jubjub_params, &mut rng);

	let proof_params = spend_params().unwrap();

	b.iter(|| {
		groth16::create_random_proof(circuit.clone(), &proof_params, None, &mut rng)
			.unwrap();
	});
}

fn bench_verify_spend_proof(b: &mut Bencher) {
	let jubjub_params = JubjubBls12::new();
	let mut rng = thread_rng();
	let (circuit, public_inputs) = random_spend_proof_instance(&jubjub_params, &mut rng);

	let proof_params = spend_params().unwrap();
	let proof = groth16::create_random_proof(circuit, &proof_params, None, &mut rng)
		.unwrap();

	let verifying_key = groth16::prepare_verifying_key(&proof_params.vk);

	b.iter(|| {
		assert!(groth16::verify_proof(&verifying_key, &proof, &public_inputs[..]).unwrap());
	});
}

fn random_spend_proof_instance<'a, 'b, E, R>(jubjub_params: &'a E::Params, rng: &'b mut R)
	-> (SpendCircuit<'a, E>, Vec<E::Fr>)
	where
		E: JubjubEngine,
		R: RngCore,
{
	let generator = jubjub_params.generator(FixedGenerators::ProofGenerationKey);

	let mut value = 0;
	let mut value_nonce_old = E::Fs::zero();
	let mut privkey = E::Fs::zero();
	let mut pubkey_base_old = <edwards::Point<_, Unknown>>::zero();

	// Build an accumulator with random coins and choose one of them for the proof inputs.
	let position = 57;
	let mut merkle_tree = IncrementalMerkleTree::empty(
		MERKLE_DEPTH, <PedersenHasher<E, _>>::new(jubjub_params)
	);
	for i in 0..100 {
		let leaf_value = rng.gen::<Value>();
		let leaf_value_nonce = E::Fs::random(rng);
		let leaf_privkey = E::Fs::random(rng);
		let leaf_pubkey_base = <edwards::Point<_, Unknown>>::from(
			generator.mul(E::Fs::random(rng).into_repr(), jubjub_params)
		);
		let leaf_pubkey_raised = leaf_pubkey_base.mul(leaf_privkey, jubjub_params);
		let leaf_coin = Coin {
			position: i,
			value_comm: value_commitment(leaf_value, &leaf_value_nonce, jubjub_params).into(),
			pubkey: (leaf_pubkey_base.clone(), leaf_pubkey_raised.clone()),
		};

		let mut encoded_coin = Vec::new();
		leaf_coin.write(&mut encoded_coin).unwrap();

		if i == position {
			value = leaf_value;
			value_nonce_old = leaf_value_nonce;
			privkey = leaf_privkey;
			pubkey_base_old = leaf_pubkey_base;
			merkle_tree.track_next_leaf();
		}
		merkle_tree.push_data(&encoded_coin);
	}

	let value_nonce_new = E::Fs::random(rng);
	let pubkey_base_new = <edwards::Point<_, Unknown>>::from(
		generator.mul(E::Fs::random(rng).into_repr(), jubjub_params)
	);
	let pubkey_raised_new = pubkey_base_new.mul(privkey, jubjub_params);

	let value_comm_new = value_commitment::<E>(value, &value_nonce_new, jubjub_params);
	let nullifier = compute_nullifier(&privkey, position);
	let auth_path = merkle_tree.tracked_branch(position)
		.unwrap()
		.iter()
		.map(|hash| E::Fr::from_repr(*hash).unwrap())
		.collect::<Vec<_>>();
	let anchor = E::Fr::from_repr(merkle_tree.root()).unwrap();

	let (value_comm_new_x, value_comm_new_y) = value_comm_new.to_xy();
	let (pubkey_base_new_x, pubkey_base_new_y) = pubkey_base_new.to_xy();
	let (pubkey_raised_new_x, pubkey_raised_new_y) = pubkey_raised_new.to_xy();
	let nullifier_bits = multipack::bytes_to_bits_le(&nullifier[..]);

	let assignment = SpendAssignment {
		position,
		value,
		value_nonce_old,
		value_nonce_new,
		privkey,
		pubkey_base_old,
		pubkey_base_new,
		nullifier,
		auth_path,
		anchor,
	};
	let circuit = SpendCircuit {
		params: jubjub_params,
		merkle_depth: MERKLE_DEPTH,
		assigned: Some(assignment.clone()),
	};

	let mut public_inputs = vec![
		assignment.anchor,
		value_comm_new_x, value_comm_new_y,
		pubkey_base_new_x, pubkey_base_new_y,
		pubkey_raised_new_x, pubkey_raised_new_y,
	];
	public_inputs.extend(multipack::compute_multipacking::<E>(&nullifier_bits));

	(circuit, public_inputs)
}

fn random_range_proof_instance<'a, 'b, E, R>(jubjub_params: &'a E::Params, rng: &'b mut R)
	-> (RangeCircuit<'a, E>, Vec<E::Fr>)
	where
		E: JubjubEngine,
		R: RngCore,
{
	let value = rng.gen::<Value>();
	let nonce = E::Fs::random(rng);
	let commitment = value_commitment::<E>(value, &nonce, jubjub_params);

	let assignment = RangeAssignment {
		value,
		nonce,
	};
	let circuit = RangeCircuit {
		params: jubjub_params,
		assigned: Some(assignment.clone()),
	};

	let (commitment_x, commitment_y) = commitment.to_xy();
	let public_inputs = vec![
		commitment_x, commitment_y,
	];

	(circuit, public_inputs)
}

benchmark_group!(benches,
	bench_issue_credential, bench_verify_credential,
	bench_issue_certificate, bench_verify_certificate,
	bench_trace_certificate,
	bench_generate_range_proof, bench_verify_range_proof,
	bench_generate_spend_proof, bench_verify_spend_proof,
);
benchmark_main!(benches);
