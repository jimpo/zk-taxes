/// Defines zk-SNARK proof circuits.

pub mod certificate;
pub mod range;
pub mod spend;

pub mod tests {
	use super::*;
	use crate::primitives::MERKLE_DEPTH;

	use bellman::groth16::{generate_random_parameters, Parameters};
	use pairing::bls12_381::Bls12;
	use rand::thread_rng;
	use std::env;
	use std::fs::{create_dir, File, OpenOptions};
	use std::io;
	use std::path::PathBuf;
	use zcash_primitives::jubjub::JubjubBls12;

	pub fn certificate_params() -> io::Result<Parameters<Bls12>> { params("Certificate.dat") }
	pub fn range_params() -> io::Result<Parameters<Bls12>> { params("Range.dat") }
	pub fn spend_params() -> io::Result<Parameters<Bls12>> { params("Spend.dat") }

	pub fn generate_certificate_params() -> io::Result<()> {
		generate_params(
			"Certificate.dat",
			certificate::Circuit::without_assignment(&JubjubBls12::new())
		)
	}
	pub fn generate_range_params() -> io::Result<()> {
		generate_params(
			"Range.dat",
			range::Circuit::without_assignment(&JubjubBls12::new())
		)
	}
	pub fn generate_spend_params() -> io::Result<()> {
		generate_params(
			"Spend.dat",
			spend::Circuit::without_assignment(&JubjubBls12::new(), MERKLE_DEPTH)
		)
	}

	fn params_dir() -> io::Result<PathBuf>  {
		let current_dir = env::current_dir()?;
		Ok(current_dir.join("generated-params"))
	}

	fn params(name: &str) -> io::Result<Parameters<Bls12>> {
		let file_path = params_dir()?.join(name);
		let file = File::open(file_path)?;
		Parameters::read(file, false)
	}

	fn generate_params<C>(name: &str, circuit: C) -> io::Result<()>
		where C: bellman::Circuit<Bls12>
	{
		let params_dirpath = params_dir()?;

		match create_dir(&params_dirpath) {
			Ok(()) => {},
			Err(e) => match e.kind() {
				io::ErrorKind::AlreadyExists => {},
				_ => return Err(e),
			}
		}

		let mut rng = thread_rng();
		let proof_params = generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)
			.expect("failed to generate random parameters for Spend circuit");

		let file_path = params_dirpath.join(name);
		let file = OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.open(file_path)?;
		proof_params.write(file)
	}
}
