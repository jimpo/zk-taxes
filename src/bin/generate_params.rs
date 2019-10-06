use zk_taxes::proofs;

fn main() {
	if let Err(err) = proofs::tests::generate_certificate_params() {
		panic!(err);
	}
	if let Err(err) = proofs::tests::generate_spend_params() {
		panic!(err);
	}
}