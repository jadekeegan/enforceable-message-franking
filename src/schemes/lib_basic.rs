use crate::toolbox::lib_common::*;
use crate::toolbox::lib_mac_ggm::*;

// Ristretto
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::{RistrettoPoint, Scalar};

use ed25519_dalek::Signature;
// Signature
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use signature::Verifier;

// Moderator Properties
pub struct Moderator {
    pub pk: VerifyingKey, // Moderator Public Key
    sk: SigningKey,       // Moderator Secret Key
}

// Moderator Implementation
#[allow(clippy::new_without_default)] // avoid default since keygen is expensive
impl Moderator {
    // KeyGenMod(1^lambda)
    pub fn new() -> Self {
        let signing_key = moderator_keygen();
        let verifying_key = signing_key.verifying_key();
        Moderator {
            pk: verifying_key,
            sk: signing_key,
        }
    }

    // Register User Function
    /// Registers a user with the moderator.
    ///
    /// # Arguments
    /// * `sk_M` - Moderator Secret Key
    /// * `id` - User Identifier
    /// * `t_expiry` - Signature Expiry Time
    ///
    /// # Returns
    /// * `k_f` - Franking Key
    /// * `k_pub` - Public Key
    /// * `sig` - Moderator Signature on User Registration
    pub fn register_user(
        &self,
        id: &[u8; 32],
        t_expiry: u64,
    ) -> (FrankingKey, PublicKey, Signature) {
        // Franking Key Generation (x0, x1)
        let k_f = mac_keygen();

        // Public Key Generation (g^x0, g^x1)
        let k_pub = compute_public_key(&k_f);

        // Serialize registration data (id || k_pub || t_expiry)
        let msg: [u8; REGISTRATION_SERIALIZATION_LEN] =
            serialize_registration(id, &k_pub, t_expiry);

        // Signature over registration data
        let sig = self.sk.sign(&msg);

        (k_f, k_pub, sig)
    }

    // Moderate Function
    /// Verifies that a message has been properly franked.
    ///
    /// # Arguments
    /// * `k_f` - Franking Key
    /// * `t_expiry` - Signature Expiry Time
    /// * `id` - User Identifier
    /// * `m` - Message to be Verified
    /// * `t_msg` - Message Timestamp
    /// * `tag` - Mac Tag
    ///
    /// # Returns
    /// * `bool` - indicating validity (true) or invalidity (false)
    pub fn moderate(
        k_f: &FrankingKey,
        t_expiry: u64,
        id: &[u8; 32],
        m: &[u8],
        t_msg: u64,
        tag: &RistrettoPoint,
    ) -> bool {
        let is_time_valid = t_msg < t_expiry;
        let is_sig_valid = mac_verify(k_f, id, m, t_msg, tag);

        is_time_valid && is_sig_valid
    }
}

// Client Properties
pub struct Client {
    pub pk: RistrettoPoint, // User Public Key (g^sk)
    sk: Scalar,             // User Secret Key
}

// Client Implementation
#[allow(clippy::new_without_default)] // avoid default since keygen is expensive
impl Client {
    // KeyGenUser(1^lambda)
    pub fn new() -> Self {
        let sk = user_keygen();
        let pk = &sk * RISTRETTO_BASEPOINT_TABLE;
        Client { pk, sk }
    }

    // SessionInit Function
    /// Initializes a session for the user.
    ///
    /// # Arguments
    /// * `pk_m` - Moderator Public Key
    /// * `id` - User Identifier
    /// * `k_f` - Franking Key
    /// * `k_pub` - Public Key
    /// * `t_expiry` - Signature Expiry Time
    /// * `sig` - Moderator Signature on User Registration
    ///
    /// # Returns
    /// * `bool` - indicating success (true) or failure (false)
    pub fn session_init(
        pk_m: &VerifyingKey,
        id: &[u8; 32],
        k_f: &FrankingKey,
        k_pub: &PublicKey,
        t_expiry: u64,
        sig: &Signature,
    ) -> bool {
        // Verify FrankingKey and PublicKey
        let computed_k_pub = compute_public_key(k_f);
        let is_k_pub_valid = k_pub == &computed_k_pub;

        // Serialize message registration data and verify signature
        let msg: [u8; REGISTRATION_SERIALIZATION_LEN] = serialize_registration(id, k_pub, t_expiry);
        let is_sig_valid = pk_m.verify(&msg, sig).is_ok();

        is_k_pub_valid && is_sig_valid
    }

    // Frank Function
    /// Generates franking data for a message.
    ///
    /// # Arguments
    ///
    /// * `pk_m` - Moderator Public Key
    /// * `pk_r` - Recipient Public Key
    /// * `k_f` - Franking Key
    /// * `k_pub` - Public Key
    /// * `id` - User Identifier
    /// * `m` - Message to be Franked
    /// * `t_msg` - Message Timestamp
    ///
    /// # Returns
    /// * `FrankData` - contains the Franking AD
    pub fn frank(
        // pk_m: &VerifyingKey,
        pk_r: &RistrettoPoint,
        k_f: &FrankingKey,
        k_pub: &PublicKey,
        id: &[u8; 32],
        m: &[u8],
        t_msg: u64,
    ) -> FrankingData {
        // Generate Random Scalar Alpha
        let alpha = Scalar::random(&mut OsRng);

        // Compute R (pk_r)^alpha
        let r = alpha * pk_r;

        // Compute E_r = g^alpha
        let e_r = &alpha * RISTRETTO_BASEPOINT_TABLE;

        // Compute MAC Tag t
        let tag = mac_tag(k_f, id, m, t_msg);

        // Compute proof pi
        let pi = zk_prove(&r, k_f, k_pub, &tag, m, id, t_msg);

        // Return Franking Data
        // Q: Is it better to allocate an array for this instead of doing a tuple?
        (*k_pub, r, e_r, tag, pi)
    }

    // TODO: AcceptSession Function
    /// Determines if another user's session should be accepted.
    ///
    /// # Arguments
    /// * `pk_m` - Moderator Public Key
    /// * `id` - User Identifier
    /// * `k_pub` - Public Key
    /// * `t_expiry` - Signature Expiry Time
    /// * `sig` - Moderator Signature on User Registration
    ///
    /// # Returns
    /// * `bool` - indicating acceptance (true) or rejection (false)
    pub fn accept_session(
        pk_m: &VerifyingKey,
        id: &[u8; 32],
        k_pub: &PublicKey,
        t_expiry: u64,
        sig: &Signature,
    ) -> bool {
        // Serialize message registration data and verify signature
        let msg: [u8; REGISTRATION_SERIALIZATION_LEN] = serialize_registration(id, k_pub, t_expiry);

        // Verify signature
        pk_m.verify(&msg, sig).is_ok()
    }

    // TODO: Verify Function
    /// Verifies that a message has been properly franked.
    ///
    /// # Arguments
    /// * `pk_m` - Moderator Public Key
    /// * `pk_R` - Recipient's Public Key
    /// * `sk_R` - Recipient's Secret Key
    /// * `m` - Message to be Verified
    /// * `ad` - Franking Data
    /// * `id` - User Identifier
    /// * `t_msg` - Message Timestamp
    /// * `t_expiry` - Signature Expiry Time
    ///
    /// # Returns
    /// * `bool` - indicating validity (true) or invalidity (false)
    pub fn verify(
        // pk_m: &VerifyingKey,
        pk_r: &RistrettoPoint,
        sk_r: &Scalar,
        m: &[u8],
        ad: &FrankingData,
        id: &[u8; 32],
        t_msg: u64,
        t_expiry: u64,
    ) -> bool {
        let (k_pub, r, e_r, tag, pi) = ad;

        let recomputed_r = sk_r * e_r;
        let is_r_valid = &recomputed_r == r;
        let is_t_valid = t_msg < t_expiry;
        let is_pi_valid = zk_verify(r, k_pub, pk_r, tag, m, id, t_msg, pi);

        is_r_valid && is_t_valid && is_pi_valid
    }
}
