use crate::toolbox::lib_common::sha256_hash;

use rand::rngs::OsRng;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// Generates a franking key consisting of two random scalars.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `(Scalar, Scalar)` - Franking Key (x0, x1)
pub fn mac_keygen() -> (Scalar, Scalar) {
    let mut rng = OsRng;
    let x0 = Scalar::random(&mut rng);
    let x1 = Scalar::random(&mut rng);

    (x0, x1)
}

/// Computes the MAC tag for a given message using the franking key.
///
/// # Arguments
/// * `k_f` - Franking Key (x0, x1)
/// * `msg` - Message to be tagged
///
/// # Returns
/// * `RistrettoPoint` - MAC Tag t
pub fn mac_tag(k_f: (Scalar, Scalar), msg: &[u8]) -> RistrettoPoint {
    // Unpack franking key
    let (x0, x1) = k_f;

    // Hash message
    let hash_bytes = sha256_hash(msg);

    // Convert hash to Scalar for multiplication with x1
    let h_m = Scalar::from_bytes_mod_order(hash_bytes);

    // g^(x0 + x1 * H(m))
    let exp = x0 + (x1 * h_m);
    let t = &exp * &RISTRETTO_BASEPOINT_TABLE;

    t
}
