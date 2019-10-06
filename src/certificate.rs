use crate::proofs::certificate as certificate_proof;

use bellman::groth16;
use blake2::{VarBlake2b, digest::{Input, VariableOutput}};
use byteorder::{ByteOrder, LittleEndian};
use ff::{BitIterator, Field, PrimeField, PrimeFieldRepr};
use group::{CurveAffine, CurveProjective};
use rand::{CryptoRng, RngCore};
use std::fmt::{self, Display, Formatter};
use zcash_primitives::jubjub::{
	edwards, FixedGenerators, JubjubEngine, PrimeOrder, JubjubParams, Unknown,
};
use bellman::SynthesisError;

/// An element of the embedded elliptic curve group G_3.
type G3<E> = edwards::Point<E, Unknown>;

#[derive(Debug)]
pub enum Error {
	InvalidID,
	ProofSynthesis(SynthesisError),
}

impl Display for Error {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		match self {
			Error::InvalidID => write!(f, "user credential ID is invalid"),
			Error::ProofSynthesis(err) => write!(f, "proof synthesis error: {}", err),
		}
	}
}

impl std::error::Error for Error {
	fn cause(&self) -> Option<&dyn std::error::Error> {
		match *self {
			Error::ProofSynthesis(ref err) => Some(err),
			_ => None
		}
	}
}

pub struct PublicParams<E>
	where E: JubjubEngine
{
	challenge_domain: &'static [u8],
	jubjub_params: E::Params,
	proof_params: groth16::Parameters<E>,
	verifying_key: groth16::PreparedVerifyingKey<E>,
	generator: FixedGenerators,
	g1: E::G1Affine,
	g2: E::G2Affine,
	g3: edwards::Point<E, PrimeOrder>,
}

impl<E> PublicParams<E>
	where E: JubjubEngine
{
	fn new(jubjub_params: E::Params, proof_params: groth16::Parameters<E>) -> Self {
		let verifying_key = groth16::prepare_verifying_key(&proof_params.vk);
		let generator = FixedGenerators::ProofGenerationKey;
		let g1 = E::G1Affine::one();
		let g2 = E::G2Affine::one();
		let g3 = jubjub_params.generator(generator).clone();
		PublicParams {
			challenge_domain: b"TRACEABLE ANONYMOUS CERTIFICATE",
			jubjub_params,
			proof_params,
			verifying_key,
			generator,
			g1,
			g2,
			g3,
		}
	}
}

pub struct AuthorityKey<E>
	where E: JubjubEngine
{
	x: E::Fr,
	y: E::Fr,
	t: E::Fs,  // Tracing secret key
	pubkey: AuthorityPublicKey<E>,
}

impl<E> AuthorityKey<E>
	where E: JubjubEngine
{
	fn pubkey(&self) -> &AuthorityPublicKey<E> {
		&self.pubkey
	}
}

#[derive(Clone)]
pub struct AuthorityPublicKey<E>
	where E: JubjubEngine
{
	x_g2: E::G2,
	y_g2: E::G2,
	t_g3: G3<E>,  // Tracing public key
}

pub struct UserKey<E>
	where E: JubjubEngine
{
	// k is the secret key.
	k: E::Fs,
	// ID is the y-coordinate of K.
	k_g3: G3<E>,
}

pub struct UserCredential<E>
	where E: JubjubEngine
{
	k_g3: G3<E>,
	sigma: (E::G1, E::G1),
}

pub struct AnonymousCertificate<E>
	where E: JubjubEngine
{
	pk: (G3<E>, G3<E>),
	sigma: (E::G1, E::G1),
	tau: G3<E>,

	c: E::Fr,
	s_id: E::Fr,
	s_b: E::Fr,
	s_q: E::Fr,
	proof: groth16::Proof<E>,
}

impl<E> UserKey<E>
	where E: JubjubEngine
{
	pub fn id(&self) -> E::Fr {
		self.k_g3.to_xy().1
	}
}

impl<E> UserCredential<E>
	where E: JubjubEngine
{
	pub fn id(&self) -> E::Fr {
		self.k_g3.to_xy().1
	}
}

// where r is the prime order of Group1, Group2,
// * and GroupT. The ID corresponds, which they know the discrete logarithm m of with respect to G1.
pub fn gen_user_key<E, R>(rng: &mut R, params: &PublicParams<E>) -> UserKey<E>
	where
		E: JubjubEngine,
		R: RngCore + CryptoRng,
{
	let mut k = E::Fs::random(rng);
	let mut k_g3 = params.g3.mul(k, &params.jubjub_params);

	// Ensure sign of x is even.
	let (x, _y) = k_g3.to_xy();
	if x.into_repr().is_odd() {
		k.negate();
		k_g3 = k_g3.negate();
	}

	UserKey {
		k,
		k_g3: k_g3.into(),
	}
}

pub fn gen_authority_key<E, R>(rng: &mut R, params: &PublicParams<E>) -> AuthorityKey<E>
	where
		E: JubjubEngine,
		R: RngCore + CryptoRng,
{
	let x = E::Fr::random(rng);
	let y = E::Fr::random(rng);
	let t = E::Fs::random(rng);
	AuthorityKey {
		x,
		y,
		t,
		pubkey: AuthorityPublicKey {
			x_g2: params.g2.mul(x),
			y_g2: params.g2.mul(y),
			t_g3: params.g3.mul(t, &params.jubjub_params).into(),
		}
	}
}

/**
* The authority issues a new user credential.
*
* The user provides an id in as an element of F_r, generated using `gen_user_key`. The authority
* chooses a random scalar u. The key consists of id, U = G1^u, V = U^(x + y * id), where (U, V) is
* a Pointcheval-Sanders signature on id.
*/
pub fn issue_credential<E, R>(
	rng: &mut R,
	params: &PublicParams<E>,
	authority_key: &AuthorityKey<E>,
	id: E::Fr,
) -> Result<UserCredential<E>, Error>
	where
		E: JubjubEngine,
		R: RngCore + CryptoRng,
{
	let k_g3 = edwards::Point::get_for_y(id, false, &params.jubjub_params)
		.ok_or(Error::InvalidID)?;

	// U = G1^u
	let u = E::Fr::random(rng);
	let u_g1 = params.g1.mul(u);

	// V = U^(x + y * id)
	let mut v = id;
	v.mul_assign(&authority_key.y);
	v.add_assign(&authority_key.x);
	let mut v_g1 = u_g1.clone();
	v_g1.mul_assign(v);

	Ok(UserCredential {
		k_g3,
		sigma: (u_g1, v_g1),
	})
}

/**
* Verify that a user credential is valid with respect to some authority.
*
* They check that the relation holds:
*
* e(σ_1, X * Y^id) = e(σ_2, G2)
*/
pub fn verify_credential<E>(
	params: &PublicParams<E>,
	authority_pubkey: &AuthorityPublicKey<E>,
	cert: &UserCredential<E>,
) -> bool
	where E: JubjubEngine
{
	// e(σ_1, X * Y^id) = e(σ_2, G2)
	let mut lhs_g2 = authority_pubkey.y_g2.clone();
	lhs_g2.mul_assign(cert.id().into_repr());
	lhs_g2.add_assign(&authority_pubkey.x_g2);

	let lhs = E::pairing(cert.sigma.0.clone(), lhs_g2);
	let rhs = E::pairing(cert.sigma.1.clone(), params.g2.clone());
	lhs == rhs
}

/**
* Issue a new traceable anonymous certificate from a public credential.
*
* The issuer chooses scalars a, b, n. a, b are used to randomize σ issued by the group manager and
* n is the nonce used in the El-Gamal encryption. The member computes:
*
* A = σ_1^a
* B = (σ_2 * σ_1^b)^a
* P = (G3^n, K^n)
* τ = K * T^n
*
* NOTE: Using n as both the ElGamal nonce and pubkey blinding factor is an optimization and needs
* to be analyzed for security.
*
* P is a randomized public key of the credential owner, and τ along with P is an El-Gamal
* encryption of K.
*
* The member then produces hybrid zero-knowledge proof of knowledge:
*
* The member uses a zk-SNARK with private inputs K, n and committed input id to prove
*
* K has id as its y coordinate and its x coordinate is even
* P_1 = G3^n
* P_2 = K^n
* τ = K * T^n
*
* The member then uses a sigma proof to prove knowledge of id, a, b satisfying
*
* e(A, G2^b * X * Y^id) = e(B, G2)
*
* as well as q, the blinding factor on the D element from the zk-SNARK.
*
* The committed input wire of the zk-SNARK takes the value id.
*
* The member chooses scalars r_v, r_k, r_m and computes:
*
* R_e = e(A, G2^r_b * Y^r_id)
* R_D = H_1^id * H_2^q
*
* The member computes the random oracle challenge
*
* c = HashToScalar(msg || A || B || D || R_e || R_D)
*
* The Sigma proof consists of A, B, R_e, R_D, c, s_id, s_q where
*
* s_id = r_id + c * id
* s_q = r_q + c * q
*/
pub fn issue_certificate<E, R>(
	rng: &mut R,
	params: &PublicParams<E>,
	authority_pubkey: &AuthorityPublicKey<E>,
	credential: &UserCredential<E>,
)
	-> Result<AnonymousCertificate<E>, Error>
	where
		E: JubjubEngine,
		R: RngCore + CryptoRng,
{
	let a = E::Fr::random(rng);
	let b = E::Fr::random(rng);
	let n = E::Fs::random(rng);
	let q = E::Fr::random(rng);

	// Create zk-SNARK proof.
	let circuit = certificate_proof::Circuit {
		params: &params.jubjub_params,
		assigned: Some(certificate_proof::Assignment {
			nonce: n,
			k_g3: credential.k_g3.clone(),
			tracing_pubkey: authority_pubkey.t_g3.clone(),
		}),
	};

	let proof = groth16::create_random_proof(circuit, &params.proof_params, Some(q.clone()), rng)
		.map_err(Error::ProofSynthesis)?;
	let d_g1 = proof.d.expect("proof circuit has committed inputs; D is Some");

	// Create sigma proof.

	// A = σ_1^a
	let mut a_g1 = credential.sigma.0.clone();
	a_g1.mul_assign(a);

	// B = (σ_2 * σ_1^b)^a
	let mut b_g1 = credential.sigma.0.clone();
	b_g1.mul_assign(b);
	b_g1.add_assign(&credential.sigma.1);
	b_g1.mul_assign(a);

	// P = (G3^n, K^n)
	let p_g3 = (
		params.g3.mul(n, &params.jubjub_params).into(),
		credential.k_g3.mul(n, &params.jubjub_params).into(),
	);

	// τ = K * T^n
	let tau_g3 = authority_pubkey.t_g3
		.mul(n, &params.jubjub_params)
		.add(&credential.k_g3, &params.jubjub_params);

	// Sigma proof nonces
	let r_id = E::Fr::random(rng);
	let r_b = E::Fr::random(rng);
	let r_q = E::Fr::random(rng);

	// Sigma proof commitments

	// R_e = e(A, G2^r_b * Y^r_id)
	let mut r_e_g2 = authority_pubkey.y_g2.clone();
	r_e_g2.mul_assign(r_id);
	r_e_g2.add_assign(&params.g2.mul(r_b));
	let r_e_gt = E::pairing(a_g1, r_e_g2);

	// R_D = H_1^r_id * H_2^r_q
	assert_eq!(params.proof_params.k.len(), 1);
	let mut r_d_g1 = params.proof_params.k[0].mul(r_id.into_repr());
	r_d_g1.add_assign(&params.proof_params.vk.delta_g1.mul(r_q.into_repr()));

	// Sigma proof challenge
	let c = compute_challenge(
		params,
		a_g1.into_affine(),
		b_g1.into_affine(),
		d_g1,
		r_e_gt,
		r_d_g1.into_affine(),
	);

	// Sigma proof scalars

	// s_id = r_id + c * id
	let mut s_id = credential.id();
	s_id.mul_assign(&c);
	s_id.add_assign(&r_id);

	// s_b = r_b + c * b
	let mut s_b = b;
	s_b.mul_assign(&c);
	s_b.add_assign(&r_b);

	// s_q = r_q + c * q
	let mut s_q = q;
	s_q.mul_assign(&c);
	s_q.add_assign(&r_q);

	Ok(AnonymousCertificate {
		pk: p_g3,
		sigma: (a_g1, b_g1),
		tau: tau_g3,
		c,
		s_id,
		s_b,
		s_q,
		proof,
	})
}

fn compute_challenge<E>(
	params: &PublicParams<E>,
	d_g1: E::G1Affine,
	a_g1: E::G1Affine,
	b_g1: E::G1Affine,
	r_e_gt: E::Fqk,
	r_d_g1: E::G1Affine,
) -> E::Fr
	where E: JubjubEngine
{
	let mut hash = VarBlake2b::new_keyed(params.challenge_domain, 32);
	hash.input(a_g1.into_compressed());
	hash.input(b_g1.into_compressed());
	hash.input(d_g1.into_compressed());
	// Wow, this is awful. Field should really have a serialization.
	hash.input(format!("{}", r_e_gt).as_bytes());
	hash.input(r_d_g1.into_compressed());
	hash_result_scalar(hash)
}

/**
* Verify a traceable anonymous certificate.
*
* The verifier computes:
*
* \hat R_e = e(σ_1, G2^s_b * X^c * Y^s_id) / e(σ_2, G2)^c
* \hat R_D = H_1^s_id * H_2^s_q / D^c
* \hat c = HashToScalar(msg || σ_1 || σ_2 || D || \hat R_e || \hat R_D)
*
* then checks that \hat c = c.
*/
pub fn verify_certificate<E, R>(
	rng: &mut R,
	params: &PublicParams<E>,
	authority_pubkey: &AuthorityPublicKey<E>,
	cert: &AnonymousCertificate<E>,
) -> Result<bool, Error>
	where
		E: JubjubEngine,
		R: RngCore + CryptoRng,
{
	let d_g1 = match cert.proof.d {
		Some(d_g1) => d_g1,
		None => return Ok(false),
	};

	let mut neg_c = cert.c.clone();
	neg_c.negate();

	// R_e = e(σ_1, G2^s_b * X^c * Y^s_id) / e(σ_2, G2)^c
	let r_e_denominator = E::pairing(cert.sigma.1.clone(), params.g2.clone());
	let r_e_denominator = r_e_denominator.pow(neg_c.into_repr());

	let mut x_c = authority_pubkey.x_g2.clone();
	x_c.mul_assign(cert.c.into_repr());

	let mut y_s_id = authority_pubkey.y_g2.clone();
	y_s_id.mul_assign(cert.s_id.into_repr());

	let mut s_e_g2 = params.g2.mul(cert.s_b.into_repr());
	s_e_g2.add_assign(&x_c);
	s_e_g2.add_assign(&y_s_id);

	let mut r_e_gt = E::pairing(cert.sigma.0.clone(), s_e_g2);
	r_e_gt.mul_assign(&r_e_denominator);

	// R_D = H_1^s_id * H_2^s_q / D^c
	assert_eq!(params.proof_params.k.len(), 1);
	let mut r_d_g1 = params.proof_params.k[0].mul(cert.s_id.into_repr());
	r_d_g1.add_assign(&params.proof_params.vk.delta_g1.mul(cert.s_q.into_repr()));
	r_d_g1.add_assign(&d_g1.mul(neg_c.into_repr()));

	// Sigma proof challenge
	let c = compute_challenge(
		params,
		cert.sigma.0.into_affine(),
		cert.sigma.1.into_affine(),
		d_g1,
		r_e_gt,
		r_d_g1.into_affine(),
	);

	if c != cert.c {
		return Ok(false);
	}

	let (pubkey_base_x, pubkey_base_y) = cert.pk.0.to_xy();
	let (pubkey_raised_x, pubkey_raised_y) = cert.pk.1.to_xy();
	let (tracing_pubkey_x, tracing_pubkey_y) = authority_pubkey.t_g3.to_xy();
	let (tracing_tag_x, tracing_tag_y) = cert.tau.to_xy();
	let public_inputs = [
		pubkey_base_x, pubkey_base_y,
		pubkey_raised_x, pubkey_raised_y,
		tracing_pubkey_x, tracing_pubkey_y,
		tracing_tag_x, tracing_tag_y,
	];
	groth16::verify_proof(&params.verifying_key, &cert.proof, &public_inputs[..])
		.map_err(Error::ProofSynthesis)
}

/**
* The authority determines the user ID of the certificate.
*
* The user's identity is the decryption of the El-Gamal ciphertext τ in the signature.
*/
pub fn trace_certificate<E>(
	params: &PublicParams<E>,
	authority_key: &AuthorityKey<E>,
	cert: &AnonymousCertificate<E>,
) -> E::Fr
	where E: JubjubEngine
{
	// K = τ * P_1^{-t}
	let mut neg_t = authority_key.t.clone();
	neg_t.negate();

	let k_g3 = cert.pk.0
		.mul(neg_t, &params.jubjub_params)
		.add(&cert.tau, &params.jubjub_params);

	k_g3.to_xy().1
}

/**
* Interpret a 32-byte hash output as a scalar.
*
* See to_uniform and hash_to_scalar in the sapling-crypto crate.
*/
fn hash_result_scalar<F: Field, H: VariableOutput>(hash: H) -> F {
	let one = F::one();

	let mut ret = F::zero();
	hash.variable_result(|output| {
		assert_eq!(output.len(), 32);
		let mut repr: [u64; 4] = [0; 4];
		LittleEndian::read_u64_into(output, &mut repr);

		for bit in BitIterator::new(repr) {
			ret.double();

			if bit {
				ret.add_assign(&one);
			}
		}
	});
	ret
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::proofs;

	use rand::{SeedableRng, rngs::StdRng};
	use zcash_primitives::jubjub::JubjubBls12;

	#[test]
	fn end_to_end() {
		let jubjub_params = JubjubBls12::new();
		let proof_params = proofs::tests::certificate_params().unwrap();
		let params = PublicParams::new(jubjub_params, proof_params);
		let mut rng = StdRng::seed_from_u64(0);

		let authority_key = gen_authority_key(&mut rng, &params);
		let user_key = gen_user_key(&mut rng, &params);

		let credential = issue_credential(&mut rng, &params, &authority_key, user_key.id())
			.unwrap();
		assert!(verify_credential(&params, &authority_key.pubkey, &credential));

		let certificate = issue_certificate(&mut rng, &params, &authority_key.pubkey, &credential)
			.unwrap();
		assert!(verify_certificate(
			&mut rng,
			&params,
			&authority_key.pubkey,
			&certificate,
		).unwrap());

		let traced_id = trace_certificate(&params, &authority_key, &certificate);
		assert_eq!(traced_id, user_key.id());
	}
}
