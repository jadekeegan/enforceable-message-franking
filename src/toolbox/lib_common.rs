use std::time::{SystemTime, UNIX_EPOCH};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::{RistrettoPoint, Scalar};
use ed25519_dalek::SigningKey;

use rand::RngCore;
use rand::rngs::OsRng;

// Type Definitions
// Q: Is it fine to pass around these as tuples?
pub type FrankingKey = (Scalar, Scalar);
pub type PublicKey = (RistrettoPoint, RistrettoPoint);
pub type FrankingData = (
    PublicKey,
    RistrettoPoint,
    RistrettoPoint,
    RistrettoPoint,
    (),
);
pub type MessageContext = ([u8; 32], u64); // (id, t_msg)

// Fixed Length for Registration Serialization
/// id (32) + g0 (32) + g1 (32) + t_expiry (8)
pub const REGISTRATION_SERIALIZATION_LEN: usize = 32 + 32 + 32 + 8;

pub const MSG_SIZE_SCALE: [usize; 1] = [100];
pub const HOUR_OFFSET: u64 = 3_600; // 1 hour in seconds
pub const DAY_OFFSET: u64 = 86_400; // 1 day in seconds
pub const WEEK_OFFSET: u64 = 604_800; // 1 week in seconds

// Compute Timestamps for expiry and message
/// Returns the current UNIX timestamp in seconds, plus any offset.
pub fn compute_timestamp(offset_secs: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    now + offset_secs
}

// Moderator Key Generation
/// Generates a moderator signing key.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `SigningKey` - Moderator Signing Key
pub fn moderator_keygen() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

// User Key Generation
/// Generates a user secret key as a random scalar.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `Scalar` - User Secret Key
pub fn user_keygen() -> Scalar {
    Scalar::random(&mut OsRng)
}

// Compute Public Key from Franking Key
/// Computes the public key corresponding to the given franking key.
///
/// # Arguments
/// * `k_f` - Franking Key (x0, x1)
///
/// # Returns
/// * `PublicKey` - Public Key (g0, g1)
pub fn compute_public_key(k_f: &FrankingKey) -> PublicKey {
    let (x0, x1) = k_f;

    let g0: RistrettoPoint = x0 * RISTRETTO_BASEPOINT_TABLE;
    let g1: RistrettoPoint = x1 * RISTRETTO_BASEPOINT_TABLE;

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
    k_pub: &PublicKey,
    t_expiry: u64,
) -> [u8; REGISTRATION_SERIALIZATION_LEN] {
    let mut msg = [0u8; REGISTRATION_SERIALIZATION_LEN];

    // Copy id into msg (no serialization needed as it's already [u8; 32])
    msg[..32].copy_from_slice(id);

    // Serialize g0 and g1 and copy into msg
    let (g0, g1) = k_pub;
    msg[32..64].copy_from_slice(&g0.compress().to_bytes());
    msg[64..96].copy_from_slice(&g1.compress().to_bytes());

    // Serialize t_expiry and copy into msg
    msg[96..104].copy_from_slice(&t_expiry.to_le_bytes());

    msg
}

// TODO: ZK.Prove, ZK.Verify
// Chapter 19 Boneh Shoup for Proof, 19.5.3
// ZK Proof of Knowledge of MAC Tag
/// Generates a zero-knowledge proof for mac tag.
///
/// # Arguments
/// * `r` - Ristretto Point R
/// * `k_f` - Franking Key
/// * `(k_pub, tag)` - Public Key and MAC Tag
/// * `m` - Message
/// * `id` - User Identifier
/// * `t_msg` - Message Timestamp
pub fn zk_prove(
    r: &RistrettoPoint,
    k_f: &FrankingKey,
    k_pub: &PublicKey,
    tag: &RistrettoPoint,
    m: &[u8],
    id: &[u8; 32],
    t_msg: u64,
) -> () {
    unimplemented!()
}

// ZK Proof Verification
/// Verifies the zero-knowledge proof for mac tag.
///
/// # Arguments
/// * `r` - Ristretto Point R
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
pub fn zk_verify(
    r: &RistrettoPoint,
    k_pub: &PublicKey,
    pk_r: &RistrettoPoint,
    tag: &RistrettoPoint,
    m: &[u8],
    id: &[u8; 32],
    t_msg: u64,
    pi: &(),
) -> bool {
    unimplemented!()
}
