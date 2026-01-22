use crate::toolbox::lib_common::*;
use crate::toolbox::lib_mac_ggm::*;

// Ristretto
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::{RistrettoPoint, Scalar};

use ed25519_dalek::Signature;
// Signature
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use signature::Verifier;

// Moderator Properties
pub struct Moderator {
    sk: SigningKey, // Moderator Secret Key
}

// TODO: ZK.Prove, ZK.Verify
// Chapter 19 Boneh Shoup for Proof, 19.5.3

// Moderator Implementation
#[allow(clippy::new_without_default)] // avoid default since keygen is expensive
impl Moderator {
    // KeyGenMod(1^lambda)
    pub fn new() -> Self {
        let signing_key = moderator_keygen();
        Moderator { sk: signing_key }
    }

    // Get Moderator Public Key
    pub fn get_pk(&self) -> VerifyingKey {
        self.sk.verifying_key()
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

        // Serialize registration data
        let msg: [u8; REGISTRATION_SERIALIZATION_LEN] =
            serialize_registration(id, &k_pub, t_expiry);

        // Signature over (id || k_pub || t_expiry)
        let sig = self.sk.sign(&msg);

        (k_f, k_pub, sig)
    }

    // Moderate Function
    /// Verifies that a message has been properly franked.
    ///
    /// # Arguments
    /// * `k_f` - Franking Key
    /// * `t_expiry` - Signature Expiry Time
    /// * `m` - Message to be Verified
    /// * `ctx` - Message Context
    /// * `t` - Mac Tag
    ///
    /// # Returns
    /// * `bool` - indicating validity (true) or invalidity (false)
    pub fn moderate(
        k_f: &FrankingKey,
        t_expiry: u64,
        m: &[u8],
        ctx: &[u8],
        t: &RistrettoPoint,
    ) -> bool {
        // TODO: Replace t with actual value from ctx once scheme has been updated.
        let msg_timestamp: u64 = 0;
        let is_time_valid = msg_timestamp < t_expiry;

        let is_sig_valid = mac_verify(k_f, m, ctx, t);

        is_time_valid && is_sig_valid
    }
}

// TODO: Client Properties
pub struct Client {
    sk: Scalar, // User Secret Key
}

// Client Implementation
#[allow(clippy::new_without_default)] // avoid default since keygen is expensive
impl Client {
    // KeyGenUser(1^lambda)
    pub fn new() -> Self {
        let sk = user_keygen();
        Client { sk }
    }

    // Get User Public Key (g^sk)
    pub fn get_pk(&self) -> RistrettoPoint {
        &self.sk * RISTRETTO_BASEPOINT_TABLE
    }

    // TODO: SessionInit Function
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

    // TODO: Maybe make a FrankData struct?
    // Should have (k_pub, R, E_r, T, pi)

    // TODO: Frank Function
    /// Generates franking data for a message.
    ///
    /// # Arguments
    /// * `m` - Message to be Franked
    /// * `k_f` - Franking Key
    /// * `k_pub` - Public Key
    /// * `ctx` - Message Context
    ///
    /// # Returns
    /// * `FrankData` - contains the Franking AD
    pub fn frank() {
        unimplemented!()
    }

    // TODO: AcceptSession Function
    /// Determines if another user's session should be accepted.
    ///
    /// # Arguments
    /// * `pk_M` - Moderator Public Key
    /// * `k_pub_U` - Other User's Public Key
    /// * `t_expiry_U` - Other User's Signature Expiry Time
    /// * `ctx` - Message Context
    /// * `sig_U` - Other User's Signature
    ///
    /// # Returns
    /// * `bool` - indicating acceptance (true) or rejection (false)
    pub fn accept_session() {
        unimplemented!()
    }

    // TODO: Verify Function
    /// Verifies that a message has been properly franked.
    ///
    /// # Arguments
    /// * `pk_R` - Recipient's Public Key
    /// * `sk_R` - Recipient's Secret Key
    /// * `m` - Message to be Verified
    /// * `ctx` - Message Context
    /// * `ad` - Franking Data
    ///
    /// # Returns
    /// * `bool` - indicating validity (true) or invalidity (false)
    pub fn verify() {
        unimplemented!()
    }
}
