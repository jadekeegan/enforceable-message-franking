use std::time::{SystemTime, UNIX_EPOCH};

use curve25519_dalek::{RistrettoPoint, Scalar};
use ed25519_dalek::{SigningKey, VerifyingKey};

use rand::RngCore;
use rand::rngs::OsRng;

// Fixed Length for Registration Serialization
/// id (32) + g0 (32) + g1 (32) + t_expiry (8)
pub const REGISTRATION_SERIALIZATION_LEN: usize = 32 + 32 + 32 + 8;

pub const HOUR_OFFSET: u64 = 3_600; // 1 hour in seconds
pub const DAY_OFFSET: u64 = 86_400; // 1 day in seconds
pub const WEEK_OFFSET: u64 = 604_800; // 1 week in seconds

// Type Definitions
pub type FrankingKey = (Scalar, Scalar);
pub type FrankingPublicKey = (RistrettoPoint, RistrettoPoint);
pub type MessageContext = ([u8; 32], u64); // (id, t_msg)
pub type ClientSecretKey = Scalar;
pub type ClientPublicKey = RistrettoPoint;

// Compress Ristretto Point
/// Compresses a given Ristretto Point into its byte representation.
/// # Arguments
/// * `point` - Ristretto Point to be compressed
///
/// # Returns
/// * `[u8; 32]` - Compressed byte representation of the Ristretto Point
pub(crate) fn compress_point(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

// Compute Timestamps for expiry and message
/// Returns the current UNIX timestamp in seconds, plus any offset.
///
/// # Arguments
/// * `offset_secs` - Number of seconds to add to the current timestamp
///
/// # Returns
/// * `u64` - Computed timestamp
pub fn compute_timestamp(offset_secs: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    now + offset_secs
}

// Moderator Signature Key Generation
/// Generates moderator keys for signing and verifying.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `SigningKey` - Moderator Signing Key
/// * `VerifyingKey` - Moderator Verifying Key
pub fn moderator_sig_keygen() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();

    (sk, pk)
}

// User Key Generation
/// Generates user keys
///
/// # Arguments
/// * None
///
/// # Returns
/// * `ClientSecretKey` - User Secret Key
/// * `ClientPublicKey` - User Public Key
pub fn user_keygen() -> (ClientSecretKey, ClientPublicKey) {
    let sk = Scalar::random(&mut OsRng);
    let pk = RistrettoPoint::mul_base(&sk);

    (sk, pk)
}

// Compute Public Key from Franking Key
/// Computes the public key corresponding to the given franking key.
///
/// # Arguments
/// * `k_f` - Franking Key (x0, x1)
///
/// # Returns
/// * `FrankingPublicKey` - Public Key (g0, g1)
pub fn compute_public_key(k_f: &FrankingKey) -> FrankingPublicKey {
    let (x0, x1) = k_f;

    let g0 = RistrettoPoint::mul_base(x0);
    let g1 = RistrettoPoint::mul_base(x1);

    (g0, g1)
}

// Generate User ID
/// Generates a random 32-byte user identifier.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `id` - Randomly generated user identifier
pub fn generate_user_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);

    id
}

// Serialize User Registration Data
/// Serializes the user registration data into a fixed-size byte array.
///
/// # Arguments
/// * `id` - User Identifier
/// * `k_pub` - Public Key (g0, g1)
/// * `t_expiry` - Signature Expiry Time
///
/// # Returns
/// * `[u8; REGISTRATION_SERIALIZATION_LEN]` - Serialized Registration Data
pub fn serialize_registration(
    id: &[u8; 32],
    k_pub: &FrankingPublicKey,
    t_expiry: u64,
) -> [u8; REGISTRATION_SERIALIZATION_LEN] {
    let mut msg = [0u8; REGISTRATION_SERIALIZATION_LEN];

    // Copy id into msg (no serialization needed as it's already [u8; 32])
    msg[..32].copy_from_slice(id);

    // Serialize g0 and g1 and copy into msg
    let (g0, g1) = k_pub;
    msg[32..64].copy_from_slice(&compress_point(g0));
    msg[64..96].copy_from_slice(&compress_point(g1));

    // Serialize t_expiry and copy into msg
    msg[96..104].copy_from_slice(&t_expiry.to_le_bytes());

    msg
}

// Unit Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_timestamp() {
        for offset in [0, HOUR_OFFSET, DAY_OFFSET, WEEK_OFFSET] {
            let ts = compute_timestamp(offset);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            assert!(
                ts >= now + offset,
                "Timestamp with offset {} is less than expected",
                offset
            );
        }
    }

    #[test]
    fn test_moderator_keygen_is_unique() {
        let (sk1, pk1) = moderator_sig_keygen();
        let (sk2, pk2) = moderator_sig_keygen();

        assert_ne!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "Generated secret keys are not unique"
        );
        assert_ne!(
            pk1.to_bytes(),
            pk2.to_bytes(),
            "Generated public keys are not unique"
        );
    }

    #[test]
    fn test_user_keygen_is_unique() {
        let (sk1, pk1) = user_keygen();
        let (sk2, pk2) = user_keygen();

        assert_ne!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "Generated user secret keys are not unique"
        );
        assert_ne!(
            compress_point(&pk1),
            compress_point(&pk2),
            "Generated user public keys are not unique"
        );
    }

    #[test]
    fn test_compute_public_key_is_correct() {
        let x0 = Scalar::ONE;
        let x1 = Scalar::ONE + Scalar::ONE;

        let k_f = (x0, x1);
        let (g0, g1) = compute_public_key(&k_f);

        assert_eq!(
            g0,
            RistrettoPoint::mul_base(&x0),
            "Computed g0 is incorrect"
        );
        assert_eq!(
            g1,
            RistrettoPoint::mul_base(&x1),
            "Computed g1 is incorrect"
        );
    }

    #[test]
    fn test_generate_user_id_is_unique() {
        let id1 = generate_user_id();
        let id2 = generate_user_id();

        assert_ne!(id1, id2, "Generated user IDs are not unique");
    }

    #[test]
    fn test_serialize_registration_length() {
        let id = [0u8; 32];
        let g0 = RistrettoPoint::default();
        let g1 = RistrettoPoint::default();
        let k_pub = (g0, g1);
        let t_expiry = 1_000_000u64;

        let serialized = serialize_registration(&id, &k_pub, t_expiry);

        assert_eq!(
            serialized.len(),
            REGISTRATION_SERIALIZATION_LEN,
            "Serialized registration length is incorrect"
        );
    }

    #[test]
    fn test_serialize_registration_is_deterministic() {
        let id = [0u8; 32];
        let g0 = RistrettoPoint::default();
        let g1 = RistrettoPoint::default();
        let k_pub = (g0, g1);
        let t_expiry = 1_000_000u64;

        let serialized1 = serialize_registration(&id, &k_pub, t_expiry);
        let serialized2 = serialize_registration(&id, &k_pub, t_expiry);

        assert_eq!(
            serialized1, serialized2,
            "Serialized registration is not deterministic"
        );
    }

    #[test]
    fn test_serialize_registration_corret_contents() {
        let id = [0u8; 32];
        let g0 = RistrettoPoint::default();
        let g1 = RistrettoPoint::default();
        let k_pub = (g0, g1);
        let t_expiry = 1_000_000u64;

        let serialized = serialize_registration(&id, &k_pub, t_expiry);

        assert_eq!(&serialized[..32], &id, "Serialized id is incorrect");
        assert_eq!(
            &serialized[32..64],
            &compress_point(&g0),
            "Serialized g0 is incorrect"
        );
        assert_eq!(
            &serialized[64..96],
            &compress_point(&g1),
            "Serialized g1 is incorrect"
        );
        assert_eq!(
            &serialized[96..104],
            &t_expiry.to_le_bytes(),
            "Serialized t_expiry is incorrect"
        );
    }
}
