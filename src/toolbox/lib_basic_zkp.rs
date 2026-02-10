use crate::toolbox::lib_common::*;
use crate::toolbox::lib_mac_ggm::hash_context;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512_256};

// ZK Proof Structure
pub struct MacOrDlogZKProof {
    // Commitments
    pub t0: CompressedRistretto,     // g^r0
    pub t1: CompressedRistretto,     // g^r1
    pub t_mac: CompressedRistretto,  // g^(r0 + r1*h)
    pub t_dlog: CompressedRistretto, // Dlog commitment

    // Challenges (split))
    pub c_frank: Scalar, // Franking key challenge
    pub c_dlog: Scalar,  // Dlog challenge

    // Responses
    pub z0: Scalar,     // r0 + c*x0
    pub z1: Scalar,     // r1 + c*x1
    pub z_dlog: Scalar, // Dlog response
}

// ZK Proof of Knowledge of MAC Tag
/// Generates a zero-knowledge proof for mac tag.
///
/// # Arguments
/// * `r_point` - Ristretto Point R
/// * `k_f` - Franking Key
/// * `tag` - MAC Tag
/// * `m` - Message
/// * `t_msg` - Message Timestamp
/// * `ctx` - Session Context
///     
/// # Returns
/// * `MacOrDlogZKProof` - ZK Proof of Knowledge of MAC Tag
pub fn zk_mac_dlog_prove(
    r_point: &CompressedRistretto,
    k_f: &FrankingKey,
    tag: &CompressedRistretto,
    m: &[u8],
    t_msg: u64,
    ctx: &SessionContext,
) -> MacOrDlogZKProof {
    // Initialize RNG
    let mut rng = OsRng;

    // Unpack franking key
    let (x0, x1) = k_f;
    let (g0, g1) = &ctx.k_pub;

    // Compute message hash h
    let h_m = hash_context(m, &ctx.id, t_msg);

    // Generate random scalars r0, r1
    let r0 = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);

    // Compute commitment for public key
    let t0 = RistrettoPoint::mul_base(&r0).compress(); // g^r0
    let t1 = RistrettoPoint::mul_base(&r1).compress(); // g^r1

    // Compute commitment for MAC tag
    let t_mac = RistrettoPoint::mul_base(&(r0 + r1 * h_m)).compress(); // g^(r0 + r1*h)
    // Simulate DLog proof
    let c_dlog = Scalar::random(&mut rng);
    let z_dlog = Scalar::random(&mut rng);
    let t_dlog =
        (RistrettoPoint::mul_base(&z_dlog) - c_dlog * r_point.decompress().unwrap()).compress(); // g^z_dlog * R^(-c_dlog)

    // Compute fiat shamir challenge c = H(g0, g1, R, t0, t1, t_mac, t_dlog)
    let c = hash_challenge(
        [
            &g0.compress(),
            &g1.compress(),
            r_point,
            tag,
            &t0,
            &t1,
            &t_mac,
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

    MacOrDlogZKProof {
        t0,
        t1,
        t_mac,
        t_dlog,
        c_frank,
        c_dlog,
        z0,
        z1,
        z_dlog,
    }
}

// ZK Proof Verification
/// Verifies the zero-knowledge proof for mac tag.
///
/// # Arguments
/// * `r_point` - Ristretto Point R
/// * `tag` - MAC Tag
/// * `m` - Message
/// * `t_msg` - Message Timestamp
/// * `ctx` - Session Context
/// * `pi` - ZK Proof
///
/// # Returns
/// * `bool` - indicating validity (true) or invalidity (false)
pub fn zk_mac_dlog_verify(
    r_point: &CompressedRistretto,
    tag: &CompressedRistretto,
    m: &[u8],
    t_msg: u64,
    ctx: &SessionContext,
    pi: &MacOrDlogZKProof,
) -> bool {
    // Unpack proof
    let MacOrDlogZKProof {
        t0,
        t1,
        t_mac,
        t_dlog,
        c_frank,
        c_dlog,
        z0,
        z1,
        z_dlog,
    } = pi;

    // Unpack public key
    let (g0, g1) = &ctx.k_pub;

    // Recompute challenge c
    let c = hash_challenge(
        [
            &g0.compress(),
            &g1.compress(),
            r_point,
            tag,
            &t0,
            &t1,
            &t_mac,
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
    let v0 = RistrettoPoint::mul_base(z0) == t0.decompress().unwrap() + c_frank * g0;
    let v1 = RistrettoPoint::mul_base(z1) == t1.decompress().unwrap() + c_frank * g1;
    let v_mac = z_mac == t_mac.decompress().unwrap() + c_frank * tag.decompress().unwrap();
    let v_dlog = RistrettoPoint::mul_base(z_dlog)
        == t_dlog.decompress().unwrap() + c_dlog * r_point.decompress().unwrap();

    v_c && v0 && v1 && v_mac && v_dlog
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

    fn test_params() -> (
        FrankingKey,
        CompressedRistretto,
        &'static [u8],
        u64,
        SessionContext,
    ) {
        let k_f = (Scalar::from(1u64), Scalar::from(2u64));
        let k_pub = (
            RistrettoPoint::mul_base(&k_f.0),
            RistrettoPoint::mul_base(&k_f.1),
        );
        let r_point = CompressedRistretto::default();
        let m = b"Test message";
        let t_msg = 0u64;
        let ctx = SessionContext {
            id: [0u8; 32],
            k_pub,
            t_expiry: 1000u64,
        };

        (k_f, r_point, m, t_msg, ctx)
    }

    #[test]
    fn test_valid_proof_verifies() {
        // Dummy values
        let (k_f, r_point, m, t_msg, ctx) = test_params();

        // Compute mac tag
        let tag = tag(&k_f, m, &ctx.id, t_msg);

        // Compute proof on k_f and tag
        let pi = zk_mac_dlog_prove(&r_point, &k_f, &tag, m, t_msg, &ctx);

        let is_valid = zk_mac_dlog_verify(&r_point, &tag, m, t_msg, &ctx, &pi);
        assert!(is_valid);
    }

    #[test]
    fn test_wrong_franking_key_rejected() {
        // Dummy values
        let (k_f, r_point, m, t_msg, ctx) = test_params();

        // Compute mac tag
        let tag = tag(&k_f, m, &ctx.id, t_msg);

        // Compute proof on invalid k_f and tag
        let invalid_k_f = (k_f.0 + Scalar::from(1u64), k_f.1);
        let pi = zk_mac_dlog_prove(&r_point, &invalid_k_f, &tag, m, t_msg, &ctx);

        let is_valid = zk_mac_dlog_verify(&r_point, &tag, m, t_msg, &ctx, &pi);
        assert!(!is_valid);
    }

    #[test]
    fn test_wrong_tag_rejected() {
        // Dummy values
        let (k_f, r_point, m, t_msg, ctx) = test_params();

        // Compute mac tag
        let tag = tag(&k_f, m, &ctx.id, t_msg);

        // Compute proof on k_f and invalid tag
        let invalid_tag = CompressedRistretto::default();
        let pi = zk_mac_dlog_prove(&r_point, &k_f, &invalid_tag, m, t_msg, &ctx);

        let is_valid = zk_mac_dlog_verify(&r_point, &tag, m, t_msg, &ctx, &pi);
        assert!(!is_valid);
    }

    #[test]
    fn test_wrong_message_rejected() {
        // Dummy values
        let (k_f, r_point, m, t_msg, ctx) = test_params();

        // Compute mac tag
        let tag = tag(&k_f, m, &ctx.id, t_msg);

        // Compute proof on k_f and tag with invalid message
        let invalid_m = b"Invalid message";
        let pi = zk_mac_dlog_prove(&r_point, &k_f, &tag, invalid_m, t_msg, &ctx);

        let is_valid = zk_mac_dlog_verify(&r_point, &tag, invalid_m, t_msg, &ctx, &pi);
        assert!(!is_valid);
    }

    #[test]
    fn test_wrong_context_rejected() {
        // Dummy values
        let (k_f, r_point, m, t_msg, ctx) = test_params();

        // Compute mac tag
        let tag = tag(&k_f, m, &ctx.id, t_msg);

        // Compute proof on k_f and tag with invalid context
        let invalid_ctx = SessionContext {
            id: [1u8; 32],
            k_pub: ctx.k_pub,
            t_expiry: ctx.t_expiry + 1,
        };

        let pi = zk_mac_dlog_prove(&r_point, &k_f, &tag, m, t_msg, &ctx);

        let is_valid = zk_mac_dlog_verify(&r_point, &tag, m, t_msg, &invalid_ctx, &pi);
        assert!(!is_valid);
    }
}
