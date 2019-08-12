pub mod spend;

pub use spend::{Circuit, Assignment};

#[cfg(test)]
pub mod tests {
	use bellman::groth16::Parameters;
	use pairing::bls12_381::Bls12;
	use std::env;
	use std::fs::File;
	use std::io;

	pub fn spend_params() -> io::Result<Parameters<Bls12>> {
		params("Spend.dat")
	}

	fn params(name: &str) -> io::Result<Parameters<Bls12>> {
		let current_dir = env::current_dir()?;

		let file_path = current_dir
			.join("generated-params")
			.join(name);
		let file = File::open(file_path)?;

		Parameters::read(file, false)
	}
}
