use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::rngs::OsRng;

use crate::toolbox::lib_common::MessageContext;
use crate::toolbox::{
    lib_common::{FrankingKey, PublicKey},
    lib_mac_ggm::hash_context,
};

// ZK Proof Structure
pub struct MacOrDlogZKProof {
    // Commitments
    pub t0: RistrettoPoint,     // g^r0
    pub t1: RistrettoPoint,     // g^r1
    pub t_mac: RistrettoPoint,  // g^(r0 + r1*h)
    pub t_dlog: RistrettoPoint, // Dlog commitment

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
/// * `(k_pub, tag)` - Public Key and MAC Tag
/// * `m` - Message
/// * `id` - User Identifier
/// * `t_msg` - Message Timestamp
pub fn zk_mac_dlog_prove(
    r_point: &RistrettoPoint,
    k_f: &FrankingKey,
    k_pub: &PublicKey,
    tag: &RistrettoPoint,
    m: &[u8],
    ctx: MessageContext,
) -> MacOrDlogZKProof {
    // Initialize RNG
    let mut rng = OsRng;

    // Unpack franking key
    let (x0, x1) = k_f;
    let (g0, g1) = k_pub;

    // Compute message hash h
    let (id, t_msg) = ctx;
    let h_m = hash_context(&id, m, t_msg);

    // Generate random scalars r0, r1
    let r0 = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);

    // Compute commitment for public key
    let t0 = &r0 * G; // g^r0
    let t1 = &r1 * G; // g^r1

    // Compute commitment for MAC tag
    let t_mac = &(r0 + r1 * h_m) * G; // g^(r0 + r1*h)

    // Simulate DLog proof
    let c_dlog = Scalar::random(&mut rng);
    let z_dlog = Scalar::random(&mut rng);
    let t_dlog = &z_dlog * G - c_dlog * r_point; // g^z_dlog * R^(-c_dlog)

    // Compute fiat shamir challenge c = H(g0, g1, R, t0, t1, t_mac, t_dlog, id, m, t_msg)
    let c = hash_challenge([g0, g1, r_point, tag, &t0, &t1, &t_mac, &t_dlog], m, ctx);

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
/// * `k_pub` - Public Key
/// * `pk_r` - Recipient's Public Key
/// * `tag` - MAC Tag
/// * `m` - Message
/// * `id` - User Identifier
/// * `t_msg` - Message Timestamp
/// * `pi` - ZK Proof
///
/// # Returns
/// * `bool` - indicating validity (true) or invalidity (false)
pub fn zk_mac_dlog_verify(
    r_point: &RistrettoPoint,
    k_pub: &PublicKey,
    _pk_r: &RistrettoPoint,
    tag: &RistrettoPoint,
    m: &[u8],
    ctx: MessageContext,
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
    let (g0, g1) = k_pub;

    // Compute message hash h
    let (id, t_msg) = ctx;
    let h_m = hash_context(&id, m, t_msg);

    // Recompute challenge c
    let c = hash_challenge([g0, g1, r_point, tag, t0, t1, t_mac, t_dlog], m, ctx);
    let v_c = c == (c_frank + c_dlog);

    // Verify commitments
    let v0 = z0 * G == t0 + c_frank * g0;
    let v1 = z1 * G == t1 + c_frank * g1;
    let v_mac = &(z0 + z1 * h_m) * G == t_mac + c_frank * tag;
    let v_dlog = z_dlog * G == t_dlog + c_dlog * r_point;

    v_c && v0 && v1 && v_mac && v_dlog
}

pub fn hash_challenge(points: [&RistrettoPoint; 8], m: &[u8], ctx: MessageContext) -> Scalar {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    // Hash all points
    for point in points {
        hasher.update(point.compress().as_bytes());
    }

    // Hash message context
    let (id, t_msg) = ctx;
    hasher.update(id);
    hasher.update(m);
    hasher.update(t_msg.to_le_bytes());

    // Finalize hash and convert to Scalar
    let hash_bytes = hasher.finalize();
    Scalar::from_bytes_mod_order(hash_bytes.into())
}
