use std::io::Error;

use crate::toolbox::lib_basic_zkp::*;
use crate::toolbox::lib_common::*;
use crate::toolbox::lib_mac_ggm as mac;

// Ristretto
use curve25519_dalek::{RistrettoPoint, Scalar};

use ed25519_dalek::Signature;
// Signature
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use signature::Verifier;

// Structs
pub struct BasicFrankingData {
    pub k_pub: FrankingPublicKey, // Public Key (g0, g1)
    pub r_point: RistrettoPoint,  // Ristretto Point R
    pub e_r: RistrettoPoint,      // Ephemeral Ristretto Point E_r
    pub tag: RistrettoPoint,      // MAC Tag t
    pub pi: MacOrDlogZKProof,     // ZK Proof of Knowledge of MAC Tag
}

// Helper Functions

// Moderator Key Generation
/// Generates a moderator signing and verifying key pair.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `SigningKey` - Moderator Signing Key
/// * `VerifyingKey` - Moderator Verifying Key
pub fn moderator_keygen() -> (SigningKey, VerifyingKey) {
    moderator_sig_keygen()
}

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
        let (signing_key, verifying_key) = moderator_keygen();

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
    ) -> (FrankingKey, FrankingPublicKey, Signature) {
        // Franking Key Generation (x0, x1)
        let k_f = mac::keygen();

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
        &self,
        k_f: &FrankingKey,
        t_expiry: u64,
        m: &[u8],
        ctx: MessageContext,
        tag: &RistrettoPoint,
    ) -> bool {
        // Unpack context
        let (_id, t_msg) = ctx;

        let is_time_valid = t_msg < t_expiry;
        let is_sig_valid = mac::verify(k_f, m, ctx, tag);

        is_time_valid && is_sig_valid
    }
}

// Client Properties
pub struct Client {
    pub id: [u8; 32],        // User Identifier
    pub pk: ClientPublicKey, // User Public Key (g^sk)
    sk: ClientSecretKey,     // User Secret Key
}

// Client Implementation
#[allow(clippy::new_without_default)] // avoid default since keygen is expensive
impl Client {
    // KeyGenUser(1^lambda)
    pub fn new() -> Self {
        let (sk, pk) = user_keygen();
        Client {
            pk,
            sk,
            id: generate_user_id(),
        }
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
        &self,
        pk_m: &VerifyingKey,
        k_f: &FrankingKey,
        k_pub: &FrankingPublicKey,
        t_expiry: u64,
        sig: &Signature,
    ) -> bool {
        // Verify FrankingKey and PublicKey
        let computed_k_pub = compute_public_key(k_f);
        let is_k_pub_valid = k_pub == &computed_k_pub;

        // Serialize message registration data and verify signature
        let data: [u8; REGISTRATION_SERIALIZATION_LEN] =
            serialize_registration(&self.id, k_pub, t_expiry);
        let is_sig_valid = pk_m.verify(&data, sig).is_ok();

        is_k_pub_valid && is_sig_valid
    }

    // AcceptSession Function
    /// Determines if another user's session should be accepted.
    ///
    /// # Arguments
    /// * `pk_m` - Moderator Public Key
    /// * `id` - Sender User Identifier
    /// * `k_pub` - Sender Franking Public Key
    /// * `t_expiry` - Signature Expiry Time
    /// * `sig` - Moderator Signature on Sender User Registration
    ///
    /// # Returns
    /// * `bool` - indicating acceptance (true) or rejection (false)
    pub fn accept_session(
        &self,
        pk_m: &VerifyingKey,
        id: &[u8; 32],
        k_pub: &FrankingPublicKey,
        t_expiry: u64,
        sig: &Signature,
    ) -> bool {
        // Serialize message registration data and verify signature
        let msg: [u8; REGISTRATION_SERIALIZATION_LEN] = serialize_registration(id, k_pub, t_expiry);

        // Verify signature
        pk_m.verify(&msg, sig).is_ok()
    }

    // Frank Function
    /// Generates franking data for a message.
    ///
    /// # Arguments
    ///
    /// * `pk_m` - Moderator Public Key
    /// * `pk_r` - Recipient Public Key (ClientPublicKey)
    /// * `k_f` - Franking Key
    /// * `k_pub` - Public Key
    /// * `id` - User Identifier
    /// * `m` - Message to be Franked
    /// * `t_msg` - Message Timestamp
    ///
    /// # Returns
    /// * `FrankData` - contains the Franking AD
    pub fn frank(
        &self,
        // _pk_m: &VerifyingKey, (Not Used in this Implementation)
        pk_r: &ClientPublicKey,
        k_f: &FrankingKey,
        k_pub: &FrankingPublicKey,
        m: &[u8],
        ctx: MessageContext,
    ) -> BasicFrankingData {
        // Generate Random Scalar Alpha
        let alpha = Scalar::random(&mut OsRng);

        // Compute R (pk_r)^alpha
        let r = alpha * pk_r;

        // Compute E_r = g^alpha
        let e_r = RistrettoPoint::mul_base(&alpha);

        // Compute MAC Tag t
        let tag = mac::tag(k_f, m, ctx);

        // Compute proof pi
        let pi = zk_mac_dlog_prove(&r, k_f, k_pub, &tag, m, ctx);

        // Return Franking Data
        BasicFrankingData {
            k_pub: *k_pub,
            r_point: r,
            e_r,
            tag,
            pi,
        }
    }

    // Verify Function
    /// Verifies that a message has been properly franked.
    ///
    /// # Arguments
    /// * `pk_m` - Moderator Public Key
    /// * `pk_R` - Recipient's Public Key (ClientPublicKey)
    /// * `m` - Message to be Verified
    /// * `ad` - Franking Data
    /// * `id` - User Identifier
    /// * `t_msg` - Message Timestamp
    /// * `t_expiry` - Signature Expiry Time
    ///
    /// # Returns
    /// * `bool` - indicating validity (true) or invalidity (false)
    pub fn verify(
        &self,
        // pk_m: &VerifyingKey,
        pk_r: &ClientPublicKey,
        ad: &BasicFrankingData,
        m: &[u8],
        ctx: MessageContext,
        t_expiry: u64,
    ) -> Result<RistrettoPoint, Error> {
        // Unpack context
        let (_id, t_msg) = ctx;

        let BasicFrankingData {
            k_pub,
            r_point,
            e_r,
            tag,
            pi,
        } = ad;

        let recomputed_r = self.sk * e_r;
        let is_r_valid = &recomputed_r == r_point;
        let is_t_valid = t_msg < t_expiry;
        let is_pi_valid = zk_mac_dlog_verify(r_point, k_pub, pk_r, tag, m, ctx, pi);

        if is_r_valid && is_t_valid && is_pi_valid {
            Ok(*tag)
        } else {
            Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "Franking data verification failed.",
            ))
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_register_user_generates_valid_sig() {
        let moderator = Moderator::new();
        let client = Client::new();

        let t_expiry = compute_timestamp(WEEK_OFFSET);
        let (_k_f, k_pub, sig) = moderator.register_user(&client.id, t_expiry);

        let data: [u8; REGISTRATION_SERIALIZATION_LEN] =
            serialize_registration(&client.id, &k_pub, t_expiry);

        assert!(moderator.pk.verify(&data, &sig).is_ok());
    }

    #[test]
    fn test_register_user_generates_valid_keys() {
        let moderator = Moderator::new();
        let client = Client::new();

        let t_expiry = compute_timestamp(WEEK_OFFSET);
        let (k_f, k_pub, _sig) = moderator.register_user(&client.id, t_expiry);

        let (x0, x1) = k_f;
        let (g0, g1) = k_pub;

        assert!(RistrettoPoint::mul_base(&x0) == g0);
        assert!(RistrettoPoint::mul_base(&x1) == g1);
    }
}
