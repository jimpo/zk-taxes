use zk_taxes::constants::MERKLE_DEPTH;
use zk_taxes::proofs::spend;

use bellman::groth16::generate_random_parameters;
use pairing::bls12_381::Bls12;
use rand::thread_rng;
use sapling_crypto::jubjub::JubjubBls12;
use std::env;
use std::fs::{create_dir, File, OpenOptions};
use std::io;

fn open_file(name: &str) -> io::Result<File> {
	let current_dir = env::current_dir()?;

	let params_dirpath = current_dir
		.join("generated-params");
	let file_path = params_dirpath.join(name);
	println!("file_path = {}", file_path.to_str().unwrap());

	match create_dir(params_dirpath) {
		Ok(()) => {},
		Err(e) => match e.kind() {
			io::ErrorKind::AlreadyExists => {},
			_ => return Err(e),
		}
	}

	OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.open(file_path)
}

fn main() {
	let params = JubjubBls12::new();
	let mut rng = thread_rng();

	let proof_params = generate_random_parameters::<Bls12, _, _>(
		spend::Circuit::without_assignment(&params, MERKLE_DEPTH),
		&mut rng
	).expect("failed to generate random parameters for Spend circuit");

	let file = open_file("Spend.dat")
		.expect("failed to open Spend.dat");
	proof_params.write(file)
		.expect("failed to write proof parameters to file");
}