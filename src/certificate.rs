use ff::{Field, PrimeField, PrimeFieldRepr};
use group::{CurveAffine, CurveProjective};
use rand::{CryptoRng, RngCore};
use pairing::{bls12_381::Bls12, Engine};
use zcash_primitives::jubjub::{
	edwards, FixedGenerators, JubjubEngine, PrimeOrder, JubjubBls12, JubjubParams,
};

type G3<E> = edwards::Point<E, PrimeOrder>;

pub struct PublicParams<E>
	where E: JubjubEngine
{
	jubjub_params: E::Params,
	generator: FixedGenerators,
	g1: E::G1Affine,
	g2: E::G2Affine,
	g3: G3<E>,
}

impl Default for PublicParams<Bls12> {
	fn default() -> Self {
		let jubjub_params = JubjubBls12::new();
		let generator = FixedGenerators::ProofGenerationKey;
		let g1 = <Bls12 as Engine>::G1Affine::one();
		let g2 = <Bls12 as Engine>::G2Affine::one();
		let g3 = jubjub_params.generator(generator).clone();
		PublicParams {
			jubjub_params,
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
	// x_g1: E::G1,
	pub pubkey: AuthorityPublicKey<E>,
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
	id: E::Fr,
	secret: E::Fs,
}

pub struct UserCredential<E>
	where E: JubjubEngine
{
	id: E::Fr,
	sigma: (E::G1, E::G1),
}

pub struct AnonymousCertificate<E>
	where E: JubjubEngine
{
	pk: (G3<E>, G3<E>),
	sigma: (E::G1, E::G1),
	tau: (G3<E>, G3<E>),
}

// where r is the prime order of Group1, Group2,
// * and GroupT. The ID corresponswhich they know the discrete logarithm m of with respect to G1.
pub fn gen_user_key<E, R>(rng: &mut R, params: &PublicParams<E>) -> UserKey<E>
	where
		E: JubjubEngine,
		R: RngCore + CryptoRng,
{
	let mut k = E::Fs::random(rng);

	let k_g3 = params.g3.mul(k, &params.jubjub_params);
	let (x, y) = k_g3.into_xy();

	// Ensure sign of x is even.
	if x.into_repr().is_odd() {
		k.negate();
	}

	UserKey {
		id: y,
		secret: k,
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
			t_g3: params.g3.mul(t, &params.jubjub_params),
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
) -> UserCredential<E>
	where
		E: JubjubEngine,
		R: RngCore + CryptoRng,
{
	// U = G1^u
	let u = E::Fr::random(rng);
	let u_g1 = params.g1.mul(u);

	// V = U^(x + y * id)
	let mut v = id;
	v.mul_assign(&authority_key.y);
	v.add_assign(&authority_key.x);
	let mut v_g1 = u_g1.clone();
	v_g1.mul_assign(v);

	UserCredential {
		id,
		sigma: (u_g1, v_g1),
	}
}

/**
* Verify that a user credential is valid with respect to some authority.
*
* They check that the relation holds:
*
* e(σ_1, X * Y^id) = e(σ_2, G2)
*/
pub fn verify_credential<E, R>(
	rng: &mut R,
	params: &PublicParams<E>,
	authority_pubkey: &AuthorityPublicKey<E>,
	cert: &UserCredential<E>,
) -> bool
	where
		E: JubjubEngine,
		R: RngCore + CryptoRng,
{
	// e(σ_1, X * Y^id) = e(σ_2, G2)
	let mut lhs_g2 = authority_pubkey.y_g2.clone();
	lhs_g2.mul_assign(cert.id.into_repr());
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
* A = U^a
* B = (V * U^b)^a
* P = (G3^n, K^n)
* τ = K * T^n
*
* (A, B) is a randomized Pointchevel-Sanders signature, P is a randomized public key of the
* credential owner, and τ along with P is an El-Gamal encryption of K.
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
* The committed input wire of the zk-SNARK takes the value id
*
* The member chooses scalars r_v, r_k, r_m and computes:
*
* R_e = e(A, G2^r_v * Y*r_m)
* R_k = G1^r_k
* R_l = G1^r_m * T^r_k
*
* The member computes the random oracle challenge
*
* c = HashToScalar(msg || A || B || K || L || R_e || R_k || R_l)
*
* The signature consists of A, B, K, L, c, s_v, s_k, s_m where
*
* s_v = r_v + c * v
* s_k = r_k + c * k
* s_m = r_m + c * m
*/
pub fn anonymize<E, R>(
	rng: &mut R,
	params: &PublicParams<E>,
	authority_pubkey: &AuthorityPublicKey<E>,
	credential: &UserCredential<E>,
)
//) -> AnonymousCertificate<E>
	where
		E: JubjubEngine,
		R: RngCore + CryptoRng,
{
//	let pubkey = &key.pubkey;
//
//	let a = E::Fr::random(rng);
//	let b = E::Fr::random(rng);
//	let k = E::Fr::random(rng);
//
//	// A = H^u
//	let mut a_g1 = key.h_g1.clone();
//	a_g1.mul_assign(u);
//
//	// B = (W * H^v)^u
//	let mut b_g1 = key.h_g1.clone();
//	b_g1.mul_assign(v);
//	b_g1.add_assign(&key.w_g1);
//	b_g1.mul_assign(u);
}

pub fn verify_certificate<E, R>(
	rng: &mut R,
	params: &PublicParams<E>,
	authority_pubkey: &AuthorityPublicKey<E>,
	cert: AnonymousCertificate<E>,
) -> bool
	where
		E: JubjubEngine,
		R: RngCore + CryptoRng,
{
	true
}
