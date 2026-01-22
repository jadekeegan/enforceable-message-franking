use crate::toolbox::lib_common::{FrankingKey, sha256_hash};

use rand::rngs::OsRng;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

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

// MAC Tag Computation
/// Computes the MAC tag for a given message using the franking key.
///
/// # Arguments
/// * `k_f` - Franking Key (x0, x1)
/// * `m` - Message to be tagged
/// * `ctx` - Message Context
///
/// # Returns
/// * `RistrettoPoint` - MAC Tag t
pub fn mac_tag(k_f: &FrankingKey, m: &[u8], ctx: &[u8]) -> RistrettoPoint {
    // Unpack franking key
    let (x0, x1) = k_f;

    // Hash message
    let hash_bytes = sha256_hash(m, ctx);

    // Convert hash to Scalar for multiplication with x1
    let h_m = Scalar::from_bytes_mod_order(hash_bytes);

    // g^(x0 + x1 * H(m))
    let exp = *x0 + (*x1 * h_m);

    &exp * RISTRETTO_BASEPOINT_TABLE
}

// Mac Tag Verification
/// Verifies the MAC tag for a given message using the franking key.
///
/// # Arguments
/// * `k_f` - Franking Key (x0, x1)
/// * `msg` - Message to be verified
/// * `t` - MAC Tag to be verified
///
/// # Returns
/// * `bool` - indicating validity (true) or invalidity (false)
pub fn mac_verify(k_f: &FrankingKey, m: &[u8], ctx: &[u8], t: &RistrettoPoint) -> bool {
    // Compute expected tag
    let expected = mac_tag(k_f, m, ctx);

    // Check if expected tag matches provided tag
    expected == *t
}
