use std::{
    sync::LazyLock,
    time::{SystemTime, UNIX_EPOCH},
};

use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha512;
use signature::{Signer, Verifier};

use crate::toolbox::lib_mac_ggm as mac;

// Fixed Length for Registration Serialization
/// id (32) + g0 (32) + g1 (32) + t_expiry (8)
pub const REGISTRATION_SERIALIZATION_LEN: usize = 32 + 32 + 32 + 8;

pub const HOUR_OFFSET: u64 = 3_600; // 1 hour in seconds
pub const DAY_OFFSET: u64 = 86_400; // 1 day in seconds
pub const WEEK_OFFSET: u64 = 604_800; // 1 week in seconds

// Generators for Pedersen Multi-Commitment
pub static G0: LazyLock<RistrettoPoint> =
    LazyLock::new(|| RistrettoPoint::hash_from_bytes::<Sha512>(b"base g0"));
pub static G1: LazyLock<RistrettoPoint> =
    LazyLock::new(|| RistrettoPoint::hash_from_bytes::<Sha512>(b"base g1"));
pub static H: LazyLock<RistrettoPoint> =
    LazyLock::new(|| RistrettoPoint::hash_from_bytes::<Sha512>(b"base h"));

// Type Definitions
pub type FrankingKey = (Scalar, Scalar);
pub type PublicFrankingKey = RistrettoPoint;
pub type ClientSecretKey = Scalar;
pub type ClientPublicKey = RistrettoPoint;
pub type ClientId = [u8; 32];

// Compressed version for communication
pub type CompressedPublicFrankingKey = CompressedRistretto;

pub struct SessionContext {
    pub id: ClientId,             // User Identifier
    pub k_pub: PublicFrankingKey, // Franking Public Key (g0, g1)
    pub t_expiry: u64,            // Signature Expiry Time
}
impl SessionContext {
    pub fn compress(&self) -> CompressedSessionContext {
        CompressedSessionContext {
            id: self.id,
            k_pub: self.k_pub.compress(),
            t_expiry: self.t_expiry,
        }
    }
}

pub struct CompressedSessionContext {
    pub id: ClientId,                       // User Identifier
    pub k_pub: CompressedPublicFrankingKey, // Compressed Franking Public Key (g0, g1)
    pub t_expiry: u64,                      // Signature Expiry Time
}
impl CompressedSessionContext {
    pub fn decompress(&self) -> SessionContext {
        SessionContext {
            id: self.id,
            k_pub: self.k_pub.decompress().unwrap(),
            t_expiry: self.t_expiry,
        }
    }
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

// Compute Pedersen Multi-Commitment
/// Computes the Pedersen multi-commitment for the given scalars and randomness.
///
/// # Arguments
/// * `s0` - Scalar to be multiplied with generator G0
/// * `s1` - Scalar to be multiplied with generator G1
/// * `r` - Randomness for the Pedersen commitment
///
/// # Returns
/// * `RistrettoPoint` - The computed Pedersen multi-commitment (G0^s0 * G1^s1 * H^r)
pub fn compute_pedersen_multicomm(s0: &Scalar, s1: &Scalar, r: &Scalar) -> RistrettoPoint {
    let g0 = s0 * (*G0);
    let g1 = s1 * (*G1);
    let h = r * (*H);

    g0 + g1 + h
}

// Compute Public Key from Franking Key
/// Computes the public key corresponding to the given franking key.
///
/// # Arguments
/// * `k_f` - Franking Key (x0, x1)
/// * `r` - Random Scalar for Pedersen Commitment
///
/// # Returns
/// * `PublicFrankingKey` - Pedersen Multi-Commitment (g_0^x0 * g_1^x1 * h^r)
pub fn compute_public_key(k_f: &FrankingKey, r: &Scalar) -> PublicFrankingKey {
    let (x0, x1) = k_f;

    compute_pedersen_multicomm(x0, x1, r)
}

// Generate User ID
/// Generates a random 32-byte user identifier.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `id` - Randomly generated user identifier
pub fn generate_user_id() -> ClientId {
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);

    id
}

// Register User
/// Registers a user with the moderator.
///
/// # Arguments
/// * `sk_m` - Moderator Secret Key
/// * `id` - User Identifier
/// * `t_expiry` - Signature Expiry Time
///
/// # Returns
/// * `k_f` - Franking Key
/// * `r` - Randomness for Pedersen commitment
/// * `compressed_k_pub` - CompressedPublicFrankingKey for communication
/// * `sig` - Moderator Signature on User Registration
pub fn issue_cert(
    sk_m: &SigningKey,
    id: &ClientId,
    t_expiry: u64,
) -> (FrankingKey, Scalar, CompressedPublicFrankingKey, Signature) {
    // Franking Key Generation (x0, x1)
    let k_f = mac::keygen();

    // Public Key Generation (g^x0, g^x1)
    let r = Scalar::random(&mut OsRng); // Random scalar for Pedersen commitment
    let k_pub = compute_public_key(&k_f, &r);

    // Construct session context for serialization
    let ctx = SessionContext {
        id: *id,
        k_pub,
        t_expiry,
    };

    // Serialize registration data (id || k_pub || t_expiry)
    let msg: [u8; REGISTRATION_SERIALIZATION_LEN] = serialize_registration(&ctx);

    // Signature over registration data
    let sig = sk_m.sign(&msg);

    let compressed_k_pub = k_pub.compress();
    (k_f, r, compressed_k_pub, sig)
}

// Session Init
/// Initializes a session for a client.
///
/// # Arguments
/// * `pk_m` - Moderator Verifying Key
/// * `k_f` - Franking Key
/// * `r` - Random Scalar for Pedersen Commitment
/// * `ctx` - Session Context
/// * `sig` - Moderator Signature on User Registration
///
/// # Returns
/// * `bool` - indicating validity (true) or invalidity (false)
pub fn session_init(
    pk_m: &VerifyingKey,
    k_f: &FrankingKey,
    r: &Scalar,
    ctx: &CompressedSessionContext,
    sig: &Signature,
) -> bool {
    let decompressed_ctx = ctx.decompress();

    // Verify FrankingKey and PublicKey
    let computed_k_pub = compute_public_key(k_f, r);
    let is_k_pub_valid = decompressed_ctx.k_pub == computed_k_pub;

    // Serialize message registration data and verify signature
    let data: [u8; REGISTRATION_SERIALIZATION_LEN] = serialize_registration(&decompressed_ctx);
    let is_sig_valid = pk_m.verify(&data, sig).is_ok();

    is_k_pub_valid && is_sig_valid
}

// Accept Session
/// Determines if another user's session should be accepted.
///
/// # Arguments
/// * `pk_m` - Moderator Verifying Key
/// * `ctx` - Session Context
/// * `sig` - Moderator Signature on User Registration
///
/// # Returns
/// * `bool` - indicating acceptance (true) or rejection (false)
pub fn accept_session(
    pk_m: &VerifyingKey,
    ctx: &CompressedSessionContext,
    sig: &Signature,
) -> bool {
    let decompressed_ctx = ctx.decompress();

    // Serialize message registration data and verify signature
    let msg: [u8; REGISTRATION_SERIALIZATION_LEN] = serialize_registration(&decompressed_ctx);

    // Verify signature
    pk_m.verify(&msg, sig).is_ok()
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
pub fn serialize_registration(ctx: &SessionContext) -> [u8; REGISTRATION_SERIALIZATION_LEN] {
    let mut msg = [0u8; REGISTRATION_SERIALIZATION_LEN];

    // Copy id into msg (no serialization needed as it's already [u8; 32])
    msg[..32].copy_from_slice(&ctx.id);
    // Serialize g0 and g1 and copy into msg
    msg[32..64].copy_from_slice(ctx.k_pub.compress().as_bytes());

    // Serialize t_expiry and copy into msg
    msg[64..72].copy_from_slice(&ctx.t_expiry.to_le_bytes());

    msg
}

// Unit Tests
#[cfg(test)]
mod tests {
    use super::*;

    fn test_session_context() -> SessionContext {
        SessionContext {
            id: [0u8; 32],
            k_pub: RistrettoPoint::default(),
            t_expiry: 1_000_000u64,
        }
    }

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
        assert_ne!(pk1, pk2, "Generated user public keys are not unique");
    }

    #[test]
    fn test_compute_public_key_is_correct() {
        let x0 = Scalar::ONE;
        let x1 = Scalar::ONE + Scalar::ONE;

        let k_f = (x0, x1);
        let r = Scalar::random(&mut OsRng);
        let k_pub = compute_public_key(&k_f, &r);

        assert_eq!(k_pub, (x0 * (*G0)) + (x1 * (*G1)) + (r * (*H)));
    }

    #[test]
    fn test_generate_user_id_is_unique() {
        let id1 = generate_user_id();
        let id2 = generate_user_id();

        assert_ne!(id1, id2, "Generated user IDs are not unique");
    }

    #[test]
    fn test_serialize_registration_length() {
        let ctx = test_session_context();
        let serialized = serialize_registration(&ctx);

        assert_eq!(
            serialized.len(),
            REGISTRATION_SERIALIZATION_LEN,
            "Serialized registration length is incorrect"
        );
    }

    #[test]
    fn test_serialize_registration_is_deterministic() {
        let ctx = test_session_context();

        let serialized1 = serialize_registration(&ctx);
        let serialized2 = serialize_registration(&ctx);

        assert_eq!(
            serialized1, serialized2,
            "Serialized registration is not deterministic"
        );
    }

    #[test]
    fn test_serialize_registration_correct_contents() {
        let ctx = test_session_context();

        let serialized = serialize_registration(&ctx);

        assert_eq!(&serialized[..32], &ctx.id, "Serialized id is incorrect");
        assert_eq!(
            &serialized[32..64],
            ctx.k_pub.compress().as_bytes(),
            "Serialized k_pub is incorrect"
        );
        assert_eq!(
            &serialized[64..72],
            &ctx.t_expiry.to_le_bytes(),
            "Serialized t_expiry is incorrect"
        );
    }
}
