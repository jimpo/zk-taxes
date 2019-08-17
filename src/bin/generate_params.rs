use zk_taxes::proofs;

fn main() {
	if let Err(err) = proofs::tests::generate_spend_params() {
		panic!(err);
	}
}