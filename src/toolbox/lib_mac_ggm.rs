use crate::toolbox::lib_common::{FrankingKey, MessageContext};

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
pub fn keygen() -> FrankingKey {
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
pub fn hash_context(m: &[u8], ctx: MessageContext) -> Scalar {
    let mut hasher = Sha256::new();

    let (id, t_msg) = ctx;
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
pub fn tag(k_f: &FrankingKey, m: &[u8], ctx: MessageContext) -> RistrettoPoint {
    // Unpack franking key
    let (x0, x1) = k_f;

    // Hash message context
    let h_m = hash_context(m, ctx);

    // g^(x0 + x1 * H(m))
    let exp = *x0 + (*x1 * h_m);

    RistrettoPoint::mul_base(&exp)
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
pub fn verify(k_f: &FrankingKey, m: &[u8], ctx: MessageContext, tag: &RistrettoPoint) -> bool {
    // Compute expected tag
    let expected = self::tag(k_f, m, ctx);

    // Check if expected tag matches provided tag
    expected == *tag
}

// Unit Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_keygen_is_unique() {
        let k_f1 = keygen();
        let k_f2 = keygen();

        assert_ne!(k_f1, k_f2, "Generated franking keys are not unique");
    }

    #[test]
    fn test_hash_context_is_unique_for_different_messages() {
        let m1 = b"Test message 1";
        let m2 = b"Test message 2";
        let ctx = ([0u8; 32], 1_000_000u64);

        let h1 = hash_context(m1, ctx);
        let h2 = hash_context(m2, ctx);

        assert_ne!(
            h1, h2,
            "Hash context outputs are not unique for different messages"
        );
    }

    #[test]
    fn test_hash_context_is_deterministic() {
        let m = b"Test message";
        let ctx = ([0u8; 32], 1_000_000u64);

        let h1 = hash_context(m, ctx);
        let h2 = hash_context(m, ctx);

        assert_eq!(h1, h2, "Hash context is not deterministic");
    }

    #[test]
    fn test_mac_tag_is_correct() {
        let k_f = (Scalar::ONE, Scalar::ONE + Scalar::ONE);
        let m = b"Test message";
        let ctx = ([0u8; 32], 1_000_000u64);

        let tag = tag(&k_f, m, ctx);
        let expected_exp = k_f.0 + (k_f.1 * hash_context(m, ctx));
        let expected_tag = RistrettoPoint::mul_base(&expected_exp);

        assert_eq!(tag, expected_tag, "Computed MAC tag is incorrect");
    }

    #[test]
    fn test_mac_tag_is_unique_for_different_messages() {
        let k_f = keygen();
        let m1 = b"Test message 1";
        let m2 = b"Test message 2";
        let ctx = ([0u8; 32], 1_000_000u64);

        let tag1 = tag(&k_f, m1, ctx);
        let tag2 = tag(&k_f, m2, ctx);

        assert_ne!(tag1, tag2, "MAC tags are not unique for different messages");
    }

    #[test]
    fn test_mac_tag_is_deterministic() {
        let k_f = keygen();
        let m = b"Test message";
        let ctx = ([0u8; 32], 1_000_000u64);

        let tag1 = tag(&k_f, m, ctx);
        let tag2 = tag(&k_f, m, ctx);

        assert_eq!(tag1, tag2, "MAC tag is not deterministic");
    }

    #[test]
    fn test_mac_verify_correctness() {
        let k_f = keygen();
        let m = b"Test message";
        let ctx = ([0u8; 32], 1_000_000u64);

        let tag = tag(&k_f, m, ctx);
        let is_valid = verify(&k_f, m, ctx, &tag);

        assert!(is_valid, "MAC verification failed for valid tag");
    }

    #[test]
    fn test_mac_verify_invalidity() {
        let k_f = keygen();
        let m = b"Test message";
        let ctx = ([0u8; 32], 1_000_000u64);

        let invalid_tag = RistrettoPoint::default();

        let is_valid = verify(&k_f, m, ctx, &invalid_tag);

        assert!(
            !is_valid,
            "MAC verification incorrectly passed for invalid tag"
        );
    }
}
