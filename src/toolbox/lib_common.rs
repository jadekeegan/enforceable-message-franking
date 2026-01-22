use ed25519_dalek::SigningKey;

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

// Moderator Key Generation
/// Generates a moderator signing key.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `SigningKey` - Moderator Signing Key
pub fn moderator_keygen() -> SigningKey {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);

    signing_key
}

// SHA-256 Hash Function
/// Computes SHA-256 hash and returns the hash as a byte array.
///
/// # Arguments
/// * `data` - Input data to be hashed
///
/// # Returns
/// * `[u8; 32]` - SHA-256 hash of the input data as a 32-byte array
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let res = hasher.finalize();

    // Converts GenericArray to [u8; 32] safely since SHA-256 always produces 32 bytes
    res.into()
}
