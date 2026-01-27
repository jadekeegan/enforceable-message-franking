use crate::toolbox::lib_common::FrankingKey;

use rand::rngs::OsRng;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use sha2::{Digest, Sha256};

// MAC Key Generation
/// Generates a franking key consisting of two random scalars.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `FrankingKey` - Franking Key (x0, x1)
pub fn mac_keygen() -> FrankingKey {
    let mut rng = OsRng;
    let x0 = Scalar::random(&mut rng);
    let x1 = Scalar::random(&mut rng);

    (x0, x1)
}

// SHA-256 Hash Function for Message Context
/// Computes SHA-256 hash and returns the hash as a byte array.
///
/// # Arguments
/// * `id` - User Identifier
/// * `m` - Message
/// * `t_msg` - Message Timestamp
///
/// # Returns
/// * `[u8; 32]` - SHA-256 hash of the input data as a 32-byte array
pub fn hash_context(id: &[u8; 32], m: &[u8], t_msg: u64) -> Scalar {
    let mut hasher = Sha256::new();

    hasher.update(id);
    hasher.update(m);
    hasher.update(t_msg.to_le_bytes());

    let hash_bytes = hasher.finalize();

    Scalar::from_bytes_mod_order(hash_bytes.into())
}

// MAC Tag Computation
/// Computes the MAC tag for a given message using the franking key.
///
/// # Arguments
/// * `k_f` - Franking Key (x0, x1)
/// * `id` - User Identifier
/// * `m` - Message to be tagged
/// * `t_msg` - Message Timestamp
///
/// # Returns
/// * `RistrettoPoint` - MAC Tag t
pub fn mac_tag(k_f: &FrankingKey, id: &[u8; 32], m: &[u8], t_msg: u64) -> RistrettoPoint {
    // Unpack franking key
    let (x0, x1) = k_f;

    // Hash message context
    let h_m = hash_context(id, m, t_msg);

    // g^(x0 + x1 * H(m))
    let exp = *x0 + (*x1 * h_m);

    &exp * G
}

// Mac Tag Verification
/// Verifies the MAC tag for a given message using the franking key.
///
/// # Arguments
/// * `k_f` - Franking Key (x0, x1)
/// * `id` - User Identifier
/// * `msg` - Message to be verified
/// * `t_msg` - Message Timestamp
/// * `tag` - MAC Tag to be verified
///
/// # Returns
/// * `bool` - indicating validity (true) or invalidity (false)
pub fn mac_verify(
    k_f: &FrankingKey,
    id: &[u8; 32],
    m: &[u8],
    t_msg: u64,
    tag: &RistrettoPoint,
) -> bool {
    // Compute expected tag
    let expected = mac_tag(k_f, id, m, t_msg);

    // Check if expected tag matches provided tag
    expected == *tag
}
