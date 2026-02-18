use crate::toolbox::lib_common::*;
use crate::toolbox::lib_elgamal_enc::*;
use crate::toolbox::lib_mac_ggm::hash_context;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512_256};

// ZK Proof Structure
pub struct MacOrDlogZKProof {
    // Commitments
    pub t_frank: CompressedRistretto, // g0^r0 * g1^r1 * H^r
    pub t_c1: CompressedRistretto,    // g^r2
    pub t_c2: CompressedRistretto,    // pk_enc^r2 * g^(r0 + r1*h)
    pub t_dlog: CompressedRistretto,  // Dlog commitment

    // Challenges (split))
    pub c_frank: Scalar, // Franking key challenge
    pub c_dlog: Scalar,  // Dlog challenge

    // Responses
    pub z0: Scalar,      // r0 + c_frank * x0
    pub z1: Scalar,      // r1 + c_frank * x1
    pub z_frank: Scalar, // r2 + c_frank * r (for Pedersen commitment)
    pub z_enc: Scalar,   // ElGamal encryption response
    pub z_dlog: Scalar,  // Dlog response
}

// ZK Proof of Knowledge of MAC Tag
/// Generates a zero-knowledge proof for mac tag.
///
/// # Arguments
/// * `r_point` - Ristretto Point R
/// * `k_f` - Franking Key
/// * `r` - Random Scalar for Pedersen Commitment
/// * `r_enc` - Random scalar used in ElGamal encryption
/// * `pk_enc` - ElGamal Public Key
/// * `enc_tag` - ElGamal Encrypted MAC Tag
/// * `m` - Message
/// * `t_msg` - Message Timestamp
/// * `ctx` - Session Context
pub fn zk_mac_dlog_prove(
    r_point: &CompressedRistretto,
    k_f: &FrankingKey,
    r: &Scalar,
    r_enc: &Scalar,
    pk_enc: &ElGamalPublicKey,
    enc_tag: &ElGamalCiphertext,
    m: &[u8],
    t_msg: u64,
    ctx: &SessionContext,
) -> MacOrDlogZKProof {
    // Initialize RNG
    let mut rng = OsRng;

    // Unpack franking key
    let (x0, x1) = k_f;

    // Compute message hash h
    let h_m = hash_context(m, &ctx.id, t_msg);

    // Generate random scalars r0, r1, r2
    let r0 = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);

    // Compute commitment for franking key
    let t_frank = compute_pedersen_multicomm(&r0, &r1, &r2).compress(); // g0^r0 * g1^r1 * H^r2

    // Compute commitment for ElGamal encryption of MAC tag
    let t_c1 = RistrettoPoint::mul_base(&r2).compress(); // g^r2
    let t_c2 = (pk_enc * r2 + RistrettoPoint::mul_base(&(r0 + r1 * h_m))).compress(); // pk_enc^r2 * g^(r0 + r1*h)

    // Simulate DLog proof
    let c_dlog = Scalar::random(&mut rng);
    let z_dlog = Scalar::random(&mut rng);
    let t_dlog =
        (RistrettoPoint::mul_base(&z_dlog) - c_dlog * r_point.decompress().unwrap()).compress(); // g^z_dlog * R^(-c_dlog)

    // Compute fiat shamir challenge c = H(k_pub || R || T (c1, c2) || t_frank || t_c1 || t_c2 || t_dlog || id || t_msg || m)
    let c = hash_challenge(
        [
            &ctx.k_pub.compress(),
            r_point,
            &enc_tag.0,
            &enc_tag.1,
            &t_frank,
            &t_c1,
            &t_c2,
            &t_dlog,
        ],
        m,
        &ctx.id,
        t_msg,
    );

    // Compute franking key challenge
    let c_frank = c - c_dlog;

    // Compute responses
    let z0 = r0 + c_frank * x0;
    let z1 = r1 + c_frank * x1;
    let z_frank = r2 + c_frank * r; // Response for ElGamal encryption randomness
    let z_enc = r2 + c_frank * r_enc;

    MacOrDlogZKProof {
        t_frank,
        t_c1,
        t_c2,
        t_dlog,
        c_frank,
        c_dlog,
        z0,
        z1,
        z_frank,
        z_dlog,
        z_enc,
    }
}

// ZK Proof Verification
/// Verifies the zero-knowledge proof for mac tag.
///
/// # Arguments
/// * `r_point` - Ristretto Point R
/// * `pk_enc` - ElGamal Public Key
/// * `enc_tag` - ElGamal Encrypted MAC Tag
/// * `m` - Message
/// * `t_msg` - Message Timestamp
/// * `ctx` - Session Context
/// * `pi` - ZK Proof
///
/// # Returns
/// * `bool` - indicating validity (true) or invalidity (false)
pub fn zk_mac_dlog_verify(
    r_point: &CompressedRistretto,
    pk_enc: &ElGamalPublicKey,
    enc_tag: &ElGamalCiphertext,
    m: &[u8],
    t_msg: u64,
    ctx: &SessionContext,
    pi: &MacOrDlogZKProof,
) -> bool {
    // Unpack proof
    let MacOrDlogZKProof {
        t_frank,
        t_c1,
        t_c2,
        t_dlog,
        c_frank,
        c_dlog,
        z0,
        z1,
        z_frank,
        z_dlog,
        z_enc,
    } = pi;

    // Recompute challenge c
    // Compute fiat shamir challenge c = H(k_pub || R || T (c1, c2) || t_frank || t_c1 || t_c2 || t_dlog || id || t_msg || m)
    let c = hash_challenge(
        [
            &ctx.k_pub.compress(),
            r_point,
            &enc_tag.0,
            &enc_tag.1,
            &t_frank,
            &t_c1,
            &t_c2,
            &t_dlog,
        ],
        m,
        &ctx.id,
        t_msg,
    );

    let v_c = c == (c_frank + c_dlog);

    // Compute message hash h
    let h_m = hash_context(m, &ctx.id, t_msg);
    let z_mac = RistrettoPoint::mul_base(&(z0 + z1 * h_m));

    // Verify commitments
    let v_frank = compute_pedersen_multicomm(z0, z1, z_frank)
        == t_frank.decompress().unwrap() + c_frank * ctx.k_pub;
    let v_c1 = RistrettoPoint::mul_base(z_enc)
        == t_c1.decompress().unwrap() + c_frank * enc_tag.0.decompress().unwrap(); // g^z_enc == t_c1 * enc_tag.0^c_frank
    let v_c2 = z_enc * pk_enc + z_mac
        == t_c2.decompress().unwrap() + c_frank * enc_tag.1.decompress().unwrap(); // pk_enc^z_enc * g^(z0 + z1*h) == t_c2 * enc_tag.1^c_frank
    let v_dlog = RistrettoPoint::mul_base(z_dlog)
        == t_dlog.decompress().unwrap() + c_dlog * r_point.decompress().unwrap(); // g^z_dlog == t_dlog * R^c_dlog

    v_c && v_frank && v_c1 && v_c2 && v_dlog
}

pub fn hash_challenge(
    points: [&CompressedRistretto; 8],
    m: &[u8],
    id: &ClientId,
    t_msg: u64,
) -> Scalar {
    // Hash using Sha512_256 for Random Oracle Model
    let mut hasher = Sha512_256::new();

    // Hash all points
    for point in points {
        hasher.update(point.as_bytes());
    }

    // Hash context
    hasher.update(id);
    hasher.update(t_msg.to_le_bytes());

    // Hash message
    hasher.update(m);

    // Finalize hash and convert to Scalar
    let hash_bytes = hasher.finalize();
    Scalar::from_bytes_mod_order(hash_bytes.into())
}

// Unit Tests
#[cfg(test)]
mod test {

    use crate::toolbox::lib_mac_ggm::tag;

    use super::*;

    // Deterministic test fixture
    fn test_params() -> (
        FrankingKey,
        Scalar,
        ElGamalPublicKey,
        CompressedRistretto,
        &'static [u8],
        u64,
        SessionContext,
    ) {
        let k_f = (Scalar::from(1u64), Scalar::from(2u64));
        let r = Scalar::from(3u64);
        let k_pub = compute_pedersen_multicomm(&k_f.0, &k_f.1, &r);
        let pk_enc = RistrettoPoint::mul_base(&Scalar::from(3u64));
        let r_point = RistrettoPoint::mul_base(&Scalar::from(5u64)).compress();
        let m = b"Test message";
        let t_msg = 0u64;
        let ctx = SessionContext {
            id: [0u8; 32],      //id
            k_pub,              // k_pub
            t_expiry: 12345u64, // t_expiry
        };

        (k_f, r, pk_enc, r_point, m, t_msg, ctx)
    }

    fn test_enc_tag(
        k_f: &FrankingKey,
        pk_enc: &ElGamalPublicKey,
        m: &[u8],
        t_msg: u64,
        ctx: &SessionContext,
    ) -> (Scalar, (CompressedRistretto, CompressedRistretto)) {
        let tag = tag(k_f, m, &ctx.id, t_msg);
        let r_enc = Scalar::from(7u64);
        let enc_tag = (
            RistrettoPoint::mul_base(&r_enc).compress(),
            (r_enc * pk_enc + tag.decompress().unwrap()).compress(),
        );

        (r_enc, enc_tag)
    }

    #[test]
    fn test_valid_proof_verifies() {
        // Dummy values
        let (k_f, r, pk_enc, r_point, m, t_msg, ctx) = test_params();

        // Compute mac tag and encrypt it
        let tag = tag(&k_f, m, &ctx.id, t_msg);
        let r_enc = Scalar::from(7u64);
        let enc_tag = (
            RistrettoPoint::mul_base(&r_enc).compress(),
            (r_enc * pk_enc + tag.decompress().unwrap()).compress(),
        );

        // Compute proof on k_f and tag
        let pi = zk_mac_dlog_prove(
            &r_point, &k_f, &r, &r_enc, &pk_enc, &enc_tag, m, t_msg, &ctx,
        );

        let is_valid = zk_mac_dlog_verify(&r_point, &pk_enc, &enc_tag, m, t_msg, &ctx, &pi);
        assert!(is_valid);
    }

    #[test]
    fn test_wrong_franking_key_rejected() {
        // Dummy values
        let (k_f, r, pk_enc, r_point, m, t_msg, ctx) = test_params();

        // Compute mac tag and encrypt it
        let (r_enc, enc_tag) = test_enc_tag(&k_f, &pk_enc, m, t_msg, &ctx);

        // Compute proof on invalid k_f and tag
        let invalid_k_f = (k_f.0 + Scalar::from(1u64), k_f.1);
        let pi = zk_mac_dlog_prove(
            &r_point,
            &invalid_k_f,
            &r,
            &r_enc,
            &pk_enc,
            &enc_tag,
            m,
            t_msg,
            &ctx,
        );

        let is_valid = zk_mac_dlog_verify(&r_point, &pk_enc, &enc_tag, m, t_msg, &ctx, &pi);
        assert!(!is_valid);
    }

    #[test]
    fn test_wrong_tag_rejected() {
        // Dummy values
        let (k_f, r, pk_enc, r_point, m, t_msg, ctx) = test_params();

        // Compute mac tag and encrypt it
        let (r_enc, enc_tag) = test_enc_tag(&k_f, &pk_enc, m, t_msg, &ctx);

        // Compute proof on k_f and invalid tag
        let invalid_enc_tag = (
            RistrettoPoint::default().compress(),
            RistrettoPoint::default().compress(),
        );
        let pi = zk_mac_dlog_prove(
            &r_point,
            &k_f,
            &r,
            &r_enc,
            &pk_enc,
            &invalid_enc_tag,
            m,
            t_msg,
            &ctx,
        );

        let is_valid = zk_mac_dlog_verify(&r_point, &pk_enc, &enc_tag, m, t_msg, &ctx, &pi);

        assert!(!is_valid);
    }

    #[test]
    fn test_wrong_message_rejected() {
        // Dummy values
        let (k_f, r, pk_enc, r_point, m, t_msg, ctx) = test_params();

        // Compute mac tag and encrypt it
        let (r_enc, enc_tag) = test_enc_tag(&k_f, &pk_enc, m, t_msg, &ctx);

        // Compute proof on k_f and invalid message
        let invalid_m = b"Invalid message";
        let pi = zk_mac_dlog_prove(
            &r_point, &k_f, &r, &r_enc, &pk_enc, &enc_tag, invalid_m, t_msg, &ctx,
        );

        let is_valid = zk_mac_dlog_verify(&r_point, &pk_enc, &enc_tag, m, t_msg, &ctx, &pi);
        assert!(!is_valid);
    }

    #[test]
    fn test_wrong_context_rejected() {
        // Dummy values
        let (k_f, r, pk_enc, r_point, m, t_msg, ctx) = test_params();

        // Compute mac tag and encrypt it
        let (r_enc, enc_tag) = test_enc_tag(&k_f, &pk_enc, m, t_msg, &ctx);

        // Compute proof on k_f and tag with invalid context
        let invalid_ctx = SessionContext {
            id: [1u8; 32],
            k_pub: ctx.k_pub,
            t_expiry: ctx.t_expiry + 1,
        };
        let pi = zk_mac_dlog_prove(
            &r_point,
            &k_f,
            &r,
            &r_enc,
            &pk_enc,
            &enc_tag,
            m,
            t_msg,
            &invalid_ctx,
        );

        let is_valid = zk_mac_dlog_verify(&r_point, &pk_enc, &enc_tag, m, t_msg, &ctx, &pi);
        assert!(!is_valid);
    }
}
