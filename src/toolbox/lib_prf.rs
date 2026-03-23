use curve25519_dalek::Scalar;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::toolbox::lib_common::ClientId;

pub type PRFKey = [u8; 32];

pub fn keygen() -> PRFKey {
    let mut rng = OsRng;
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

    key
}

// PRF
/// Evaluates the PRF on input (id, t_exp) using key k_prf.
///
/// # Arguments
/// * `key` - PRF Key
/// * `id` - User Identifier
/// * `t_exp` - Expiry Time
///
/// # Returns
/// * `Scalar` - Output of the PRF as a Scalar
pub fn prf(key: &PRFKey, id: &ClientId, t_exp: u64) -> Scalar {
    let mut hasher = Sha256::new();

    hasher.update(key);
    hasher.update(id);
    hasher.update(t_exp.to_le_bytes());

    let result = hasher.finalize();

    Scalar::from_bytes_mod_order(result.into())
}
