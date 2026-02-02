use rand::rngs::OsRng;
use std::io::Error;

use crate::toolbox::lib_common::*;
use crate::toolbox::lib_elgamal_enc as elgamal;
use crate::toolbox::lib_elgamal_enc::{ElGamalCiphertext, ElGamalPublicKey, ElGamalSecretKey};
use crate::toolbox::lib_elgamal_zkp::*;
use crate::toolbox::lib_mac_ggm as mac;

use curve25519_dalek::{RistrettoPoint, Scalar};
use ed25519_dalek::Signature;
use ed25519_dalek::{SigningKey, VerifyingKey};
use signature::Verifier;

// Type Definitions
pub struct ModeratorSecretKey {
    sk_sig: SigningKey,
    sk_dec: ElGamalSecretKey,
}

pub struct ModeratorPublicKey {
    pub pk_sig: VerifyingKey,
    pub pk_enc: ElGamalPublicKey,
}

pub struct ElGamalFrankingData {
    pub k_pub: FrankingPublicKey,   // Public Key (g0, g1)
    pub r_point: RistrettoPoint,    // Ristretto Point R
    pub e_r: RistrettoPoint,        // Ephemeral Ristretto Point E_r
    pub enc_tag: ElGamalCiphertext, // Encrypted MAC Tag t
    pub pi: MacOrDlogZKProof,       // ZK Proof of Knowledge of MAC Tag
}

// Helper Functions

// Moderator Key Generation
/// Generates a moderator signature and elgamal keypairs.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `ModeratorSecretKey` - Moderator Signing and Elgamal Decryption Keys
/// * `ModeratorPublicKey` - Moderator Verifying Key and Elgamal Encryption Key
pub fn moderator_keygen() -> (ModeratorSecretKey, ModeratorPublicKey) {
    let (sk_sig, pk_sig) = moderator_sig_keygen();
    let (sk_dec, pk_enc) = elgamal::keygen();

    (
        ModeratorSecretKey { sk_sig, sk_dec },
        ModeratorPublicKey { pk_sig, pk_enc },
    )
}

// Moderator Properties
pub struct Moderator {
    pub pk: ModeratorPublicKey, // Moderator Public Key
    sk: ModeratorSecretKey,     // Moderator Secret Key
}

// Moderator Implementation
#[allow(clippy::new_without_default)] // avoid default since keygen is expensive
impl Moderator {
    // KeyGenMod(1^lambda)
    pub fn new() -> Self {
        let (sk, pk) = moderator_keygen();

        Moderator { pk, sk }
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
        register_user(&self.sk.sk_sig, id, t_expiry)
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
    /// * `enc_tag` - Mac Tag
    ///
    /// # Returns
    /// * `bool` - indicating validity (true) or invalidity (false)
    pub fn moderate(
        &self,
        k_f: &FrankingKey,
        t_expiry: u64,
        m: &[u8],
        ctx: MessageContext,
        enc_tag: &ElGamalCiphertext,
    ) -> bool {
        // Unpack context
        let (_id, t_msg) = ctx;

        let is_time_valid = t_msg < t_expiry;
        let tag = elgamal::decrypt(&self.sk.sk_dec, enc_tag);
        let is_sig_valid = mac::verify(k_f, m, ctx, &tag);

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
        pk_m: &ModeratorPublicKey,
        k_f: &FrankingKey,
        k_pub: &FrankingPublicKey,
        t_expiry: u64,
        sig: &Signature,
    ) -> bool {
        session_init(&self.id, &pk_m.pk_sig, k_f, k_pub, t_expiry, sig)
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
        pk_m: &ModeratorPublicKey,
        pk_r: &ClientPublicKey,
        k_f: &FrankingKey,
        k_pub: &FrankingPublicKey,
        m: &[u8],
        ctx: MessageContext,
    ) -> ElGamalFrankingData {
        // Generate Random Scalar Alpha
        let alpha = Scalar::random(&mut OsRng);

        // Compute R (pk_r)^alpha
        let r = alpha * pk_r;

        // Compute E_r = g^alpha
        let e_r = RistrettoPoint::mul_base(&alpha);

        // Compute MAC Tag t
        let tag = mac::tag(k_f, m, ctx);

        // Encrypt tag using ElGamal
        let (enc_tag, r_enc) = elgamal::encrypt(&pk_m.pk_enc, &tag);

        // Compute proof pi
        let pi = zk_mac_dlog_prove(&r, k_f, &r_enc, k_pub, &pk_m.pk_enc, &enc_tag, m, ctx);

        // Return Franking Data
        ElGamalFrankingData {
            k_pub: *k_pub,
            r_point: r,
            e_r,
            enc_tag,
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
        pk_m: &ModeratorPublicKey,
        pk_r: &ClientPublicKey,
        ad: &ElGamalFrankingData,
        m: &[u8],
        ctx: MessageContext,
        t_expiry: u64,
    ) -> Result<ElGamalCiphertext, Error> {
        // Unpack context
        let (_id, t_msg) = ctx;

        let ElGamalFrankingData {
            k_pub,
            r_point,
            e_r,
            enc_tag,
            pi,
        } = ad;

        let recomputed_r = self.sk * e_r;
        let is_r_valid = &recomputed_r == r_point;
        let is_t_valid = t_msg < t_expiry;
        let is_pi_valid =
            zk_mac_dlog_verify(r_point, k_pub, pk_r, &pk_m.pk_enc, enc_tag, m, ctx, pi);

        if is_r_valid && is_t_valid && is_pi_valid {
            Ok(*enc_tag)
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

        assert!(moderator.pk.pk_sig.verify(&data, &sig).is_ok());
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
