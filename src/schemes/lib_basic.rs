use crate::toolbox::lib_common::*;
use crate::toolbox::lib_mac_ggm::*;

use aes_gcm::aead::rand_core::le;
use curve25519_dalek::Scalar;
// Ristretto
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;

// Signature
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

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

    pub fn get_pk(&self) -> VerifyingKey {
        self.sk.verifying_key()
    }

    // TODO: Register User Function
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
    pub fn register_user(&self, id: &[u8; 32], t_expiry: u64) -> (FrankingKey, PublicKey, Vec<u8>) {
        // Franking Key Generation (x0, x1)
        let k_f = mac_keygen();
        let (x0, x1) = k_f;

        // Public Key Generation (g^x0, g^x1)
        let g0: RistrettoPoint = &x0 * RISTRETTO_BASEPOINT_TABLE;
        let g1: RistrettoPoint = &x1 * RISTRETTO_BASEPOINT_TABLE;
        let k_pub = (g0, g1);

        // Serialize registration data
        let msg: [u8; REGISTRATION_SERIALIZATION_LEN] =
            serialize_registration(id, &k_pub, t_expiry);

        // Signature over (id || k_pub || t_expiry)
        let sig = self.sk.sign(&msg).to_bytes().to_vec();

        (k_f, k_pub, sig)
    }

    // TODO: Moderate Function
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
        k_f: FrankingKey,
        t_expiry: u64,
        m: &[u8],
        ctx: &[u8],
        t: RistrettoPoint,
    ) -> bool {
        // TODO: Replace t with actual value from ctx once scheme has been updated.
        let msg_timestamp: u64 = 0;
        let is_time_valid = msg_timestamp < t_expiry;

        let is_sig_valid = mac_verify(&k_f, m, ctx, &t);

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

    // TODO: SessionInit Function
    /// Initializes a session for the user.
    ///
    /// # Arguments
    /// * `pk_M` - Moderator Public Key
    /// * `id_U` - User Identifier
    /// * `k_f` - Franking Key
    /// * `t_expiry` - Signature Expiry Time
    /// * `sig` - Moderator Signature on User Registration
    ///
    /// # Returns
    /// * `bool` - indicating success (true) or failure (false)
    pub fn session_init() {
        unimplemented!()
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
