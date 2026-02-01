use crate::toolbox::lib_common::*;
use crate::toolbox::lib_elgamal_enc::*;
use crate::toolbox::lib_mac_ggm::hash_context;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::rngs::OsRng;

// ZK Proof Structure
pub struct MacOrDlogZKProof {
    // Commitments
    pub t0: RistrettoPoint,     // g^r0
    pub t1: RistrettoPoint,     // g^r1
    pub t_c1: RistrettoPoint,   // g^r2
    pub t_c2: RistrettoPoint,   // pk_enc^r2 * g^(r0 + r1*h)
    pub t_dlog: RistrettoPoint, // Dlog commitment

    // Challenges (split))
    pub c_frank: Scalar, // Franking key challenge
    pub c_dlog: Scalar,  // Dlog challenge

    // Responses
    pub z0: Scalar,            // r0 + c*x0
    pub z1: Scalar,            // r1 + c*x1
    pub z_mac: RistrettoPoint, // MAC response
    pub z_enc: Scalar,         // ElGamal encryption response
    pub z_dlog: Scalar,        // Dlog response
}

// ZK Proof of Knowledge of MAC Tag
/// Generates a zero-knowledge proof for mac tag.
///
/// # Arguments
/// * `r_point` - Ristretto Point R
/// * `k_f` - Franking Key
/// * `r_enc` - Random scalar used in ElGamal encryption
/// * `k_pub` - Franking Public Key
/// * `pk_enc` - ElGamal Public Key
/// * `enc_tag` - ElGamal Encrypted MAC Tag
/// * `m` - Message
/// * `id` - User Identifier
/// * `t_msg` - Message Timestamp
pub fn zk_mac_dlog_prove(
    r_point: &RistrettoPoint,
    k_f: &FrankingKey,
    r_enc: &Scalar,
    k_pub: &FrankingPublicKey,
    pk_enc: &ElGamalPublicKey,
    enc_tag: &ElGamalCiphertext,
    m: &[u8],
    ctx: MessageContext,
) -> MacOrDlogZKProof {
    // Initialize RNG
    let mut rng = OsRng;

    // Unpack franking key
    let (x0, x1) = k_f;
    let (g0, g1) = k_pub;

    // Compute message hash h
    let h_m = hash_context(m, ctx);

    // Generate random scalars r0, r1, r2
    let r0 = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);

    // Compute commitment for public key
    let t0 = RistrettoPoint::mul_base(&r0); // g^r0
    let t1 = RistrettoPoint::mul_base(&r1); // g^r1

    // Compute commitment for ElGamal encryption of MAC tag
    let t_mac = RistrettoPoint::mul_base(&(r0 + r1 * h_m)); // g^(r0 + r1*h)
    let t_c1 = RistrettoPoint::mul_base(&r2); // g^r2
    let t_c2 = pk_enc * r2 + t_mac; // pk_enc^r2 * g^(r0 + r1*h)

    // Simulate DLog proof
    let c_dlog = Scalar::random(&mut rng);
    let z_dlog = Scalar::random(&mut rng);
    let t_dlog = RistrettoPoint::mul_base(&z_dlog) - c_dlog * r_point; // g^z_dlog * R^(-c_dlog)

    // Compute fiat shamir challenge c = H(g0, g1, R, T (c1, c2), t0, t1, t_c1, t_c2, t_dlog)
    let c = hash_challenge(
        [
            g0, g1, r_point, &enc_tag.0, &enc_tag.1, &t0, &t1, &t_c1, &t_c2, &t_dlog,
        ],
        m,
        ctx,
    );

    // Compute franking key challenge
    let c_frank = c - c_dlog;

    // Compute responses
    let z0 = r0 + c_frank * x0;
    let z1 = r1 + c_frank * x1;
    let z_mac = RistrettoPoint::mul_base(&(z0 + z1 * h_m));
    let z_enc = r2 + c_frank * r_enc;

    MacOrDlogZKProof {
        t0,
        t1,
        t_c1,
        t_c2,
        t_dlog,
        c_frank,
        c_dlog,
        z0,
        z1,
        z_dlog,
        z_mac,
        z_enc,
    }
}

// ZK Proof Verification
/// Verifies the zero-knowledge proof for mac tag.
///
/// # Arguments
/// * `r_point` - Ristretto Point R
/// * `k_pub` - Public Key
/// * `pk_r` - Recipient's Public Key
/// * `pk_enc` - ElGamal Public Key
/// * `enc_tag` - ElGamal Encrypted MAC Tag
/// * `m` - Message
/// * `id` - User Identifier
/// * `t_msg` - Message Timestamp
/// * `pi` - ZK Proof
///
/// # Returns
/// * `bool` - indicating validity (true) or invalidity (false)
pub fn zk_mac_dlog_verify(
    r_point: &RistrettoPoint,
    k_pub: &FrankingPublicKey,
    _pk_r: &ClientPublicKey,
    pk_enc: &ElGamalPublicKey,
    enc_tag: &ElGamalCiphertext,
    m: &[u8],
    ctx: MessageContext,
    pi: &MacOrDlogZKProof,
) -> bool {
    // Unpack proof
    let MacOrDlogZKProof {
        t0,
        t1,
        t_c1,
        t_c2,
        t_dlog,
        c_frank,
        c_dlog,
        z0,
        z1,
        z_dlog,
        z_mac,
        z_enc,
    } = pi;

    // Unpack public key
    let (g0, g1) = k_pub;

    // Recompute challenge c
    let c = hash_challenge(
        [
            g0, g1, r_point, &enc_tag.0, &enc_tag.1, t0, t1, t_c1, t_c2, t_dlog,
        ],
        m,
        ctx,
    );
    let v_c = c == (c_frank + c_dlog);

    // Verify commitments
    let v0 = RistrettoPoint::mul_base(z0) == t0 + c_frank * g0;
    let v1 = RistrettoPoint::mul_base(z1) == t1 + c_frank * g1;
    let v_c1 = RistrettoPoint::mul_base(z_enc) == t_c1 + c_frank * enc_tag.0;
    let v_c2 = z_enc * pk_enc + z_mac == t_c2 + c_frank * enc_tag.1;
    let v_dlog = RistrettoPoint::mul_base(z_dlog) == t_dlog + c_dlog * r_point;

    v_c && v0 && v1 && v_c1 && v_c2 && v_dlog
}

pub fn hash_challenge(points: [&RistrettoPoint; 10], m: &[u8], ctx: MessageContext) -> Scalar {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    // Hash all points
    for point in points {
        hasher.update(point.compress().as_bytes());
    }

    // Hash context
    let (id, t_msg) = ctx;
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
        FrankingPublicKey,
        ElGamalPublicKey,
        RistrettoPoint,
        &'static [u8],
        MessageContext,
    ) {
        let k_f = (Scalar::from(1u64), Scalar::from(2u64));
        let k_pub = (
            RistrettoPoint::mul_base(&k_f.0),
            RistrettoPoint::mul_base(&k_f.1),
        );
        let pk_enc = RistrettoPoint::mul_base(&Scalar::from(3u64));
        let r_point = RistrettoPoint::mul_base(&Scalar::from(5u64));
        let m = b"Test message";
        let ctx = (
            [0u8; 32], //id
            12345u64,  // t_msg
        );

        (k_f, k_pub, pk_enc, r_point, m, ctx)
    }

    #[test]
    fn test_valid_proof_verifies() {
        // Dummy values
        let (k_f, k_pub, pk_enc, r_point, m, ctx) = test_params();

        // Compute mac tag and encrypt it
        let tag = tag(&k_f, m, ctx);
        let r_enc = Scalar::from(7u64);
        let enc_tag = (RistrettoPoint::mul_base(&r_enc), r_enc * pk_enc + tag);

        // Compute proof on k_f and tag
        let pi = zk_mac_dlog_prove(&r_point, &k_f, &r_enc, &k_pub, &pk_enc, &enc_tag, m, ctx);

        let is_valid =
            zk_mac_dlog_verify(&r_point, &k_pub, &r_point, &pk_enc, &enc_tag, m, ctx, &pi);
        assert!(is_valid);
    }

    #[test]
    fn test_wrong_franking_key_rejected() {
        // Dummy values
        let (k_f, k_pub, pk_enc, r_point, m, ctx) = test_params();

        // Compute mac tag and encrypt it
        let tag = tag(&k_f, m, ctx);
        let r_enc = Scalar::from(7u64);
        let enc_tag = (RistrettoPoint::mul_base(&r_enc), r_enc * pk_enc + tag);

        // Compute proof on invalid k_f and tag
        let invalid_k_f = (k_f.0 + Scalar::from(1u64), k_f.1);
        let pi = zk_mac_dlog_prove(
            &r_point,
            &invalid_k_f,
            &r_enc,
            &k_pub,
            &pk_enc,
            &enc_tag,
            m,
            ctx,
        );

        let is_valid =
            zk_mac_dlog_verify(&r_point, &k_pub, &r_point, &pk_enc, &enc_tag, m, ctx, &pi);
        assert!(!is_valid);
    }

    #[test]
    fn test_wrong_tag_rejected() {
        // Dummy values
        let (k_f, k_pub, pk_enc, r_point, m, ctx) = test_params();

        // Compute mac tag and encrypt it
        let tag = tag(&k_f, m, ctx);
        let r_enc = Scalar::from(7u64);
        let enc_tag = (RistrettoPoint::mul_base(&r_enc), r_enc * pk_enc + tag);

        // Compute proof on k_f and invalid tag
        let invalid_enc_tag = (RistrettoPoint::default(), RistrettoPoint::default());
        let pi = zk_mac_dlog_prove(
            &r_point,
            &k_f,
            &r_enc,
            &k_pub,
            &pk_enc,
            &invalid_enc_tag,
            m,
            ctx,
        );

        let is_valid =
            zk_mac_dlog_verify(&r_point, &k_pub, &r_point, &pk_enc, &enc_tag, m, ctx, &pi);

        assert!(!is_valid);
    }

    #[test]
    fn test_wrong_message_rejected() {
        // Dummy values
        let (k_f, k_pub, pk_enc, r_point, m, ctx) = test_params();

        // Compute mac tag and encrypt it
        let tag = tag(&k_f, m, ctx);
        let r_enc = Scalar::from(7u64);
        let enc_tag = (RistrettoPoint::mul_base(&r_enc), r_enc * pk_enc + tag);

        // Compute proof on k_f and invalid message
        let invalid_m = b"Invalid message";
        let pi = zk_mac_dlog_prove(
            &r_point, &k_f, &r_enc, &k_pub, &pk_enc, &enc_tag, invalid_m, ctx,
        );

        let is_valid =
            zk_mac_dlog_verify(&r_point, &k_pub, &r_point, &pk_enc, &enc_tag, m, ctx, &pi);
        assert!(!is_valid);
    }

    #[test]
    fn test_wrong_context_rejected() {
        // Dummy values
        let (k_f, k_pub, pk_enc, r_point, m, ctx) = test_params();

        // Compute mac tag and encrypt it
        let tag = tag(&k_f, m, ctx);
        let r_enc = Scalar::from(7u64);
        let enc_tag = (RistrettoPoint::mul_base(&r_enc), r_enc * pk_enc + tag);

        // Compute proof on k_f and tag with invalid context
        let invalid_ctx = (
            [1u8; 32], // id
            54321u64,  // t_msg
        );
        let pi = zk_mac_dlog_prove(
            &r_point,
            &k_f,
            &r_enc,
            &k_pub,
            &pk_enc,
            &enc_tag,
            m,
            invalid_ctx,
        );

        let is_valid =
            zk_mac_dlog_verify(&r_point, &k_pub, &r_point, &pk_enc, &enc_tag, m, ctx, &pi);
        assert!(!is_valid);
    }
}
