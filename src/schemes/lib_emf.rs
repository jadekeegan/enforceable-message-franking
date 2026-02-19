use crate::toolbox::lib_common::*;
use crate::toolbox::lib_emf_enc as emf;
use crate::toolbox::lib_emf_enc::{EMFPublicKey, EMFSecretKey, ElGamalCiphertext};
use crate::toolbox::lib_emf_zkp::*;
use crate::toolbox::lib_mac_ggm as mac;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use ed25519_dalek::Signature;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::io::Error;

// Type Definitions
pub struct ModeratorSecretKey {
    sk_sig: SigningKey,
    sk_dec: EMFSecretKey,
}

pub struct ModeratorPublicKey {
    pub pk_sig: VerifyingKey,
    pub pk_enc: EMFPublicKey,
}

pub struct EMFFrankingData {
    pub r_point: CompressedRistretto, // Ristretto Point R
    pub e_r: CompressedRistretto,     // Ephemeral Ristretto Point E_r
    pub enc_tag: ElGamalCiphertext,   // Encrypted MAC Tag t
    pub pi: MacOrDlogZKProof,         // ZK Proof of Knowledge of MAC Tag
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
    let (sk_dec, pk_enc) = emf::keygen();

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
    pub fn issue_cert(
        &self,
        id: &ClientId,
        t_expiry: u64,
    ) -> (FrankingKey, Scalar, CompressedPublicFrankingKey, Signature) {
        issue_cert(&self.sk.sk_sig, id, t_expiry)
    }

    // Moderate Function
    /// Verifies that a message has been properly franked.
    ///
    /// # Arguments
    /// * `k_f` - Franking Key
    /// * `m` - Message to be Verified
    /// * `t_msg` - Message Timestamp
    /// * `ctx` - Session Context
    /// * `enc_tag` - Mac Tag
    ///
    /// # Returns
    /// * `bool` - indicating validity (true) or invalidity (false)
    pub fn moderate(
        &self,
        k_f: &FrankingKey,
        m: &[u8],
        t_msg: u64,
        ctx: &SessionContext,
        enc_tag: &ElGamalCiphertext,
    ) -> bool {
        let is_time_valid = t_msg < ctx.t_expiry;
        let tag = emf::decrypt(&self.sk.sk_dec, enc_tag);
        let is_tag_valid = mac::verify(k_f, m, &ctx.id, t_msg, &tag);

        is_time_valid && is_tag_valid
    }
}

// Client Properties
pub struct Client {
    pub id: ClientId,        // User Identifier
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
    /// * `k_f` - Franking Key
    /// * `r` - Random Scalar for Pedersen Commitment
    /// * `ctx` - Session Context
    /// * `sig` - Moderator Signature on User Registration
    ///
    /// # Returns
    /// * `bool` - indicating success (true) or failure (false)
    pub fn session_init(
        &self,
        pk_m: &ModeratorPublicKey,
        k_f: &FrankingKey,
        r: &Scalar,
        ctx: &CompressedSessionContext,
        sig: &Signature,
    ) -> bool {
        session_init(&pk_m.pk_sig, k_f, r, ctx, sig)
    }

    // AcceptSession Function
    /// Determines if another user's session should be accepted.
    ///
    /// # Arguments
    /// * `pk_m` - Moderator Public Key
    /// * `ctx` - Session Context
    /// * `sig` - Moderator Signature on Sender User Registration
    ///
    /// # Returns
    /// * `bool` - indicating acceptance (true) or rejection (false)
    pub fn accept_session(
        &self,
        pk_m: &VerifyingKey,
        ctx: &CompressedSessionContext,
        sig: &Signature,
    ) -> bool {
        accept_session(pk_m, ctx, sig)
    }

    // Frank Function
    /// Generates franking data for a message.
    ///
    /// # Arguments
    ///
    /// * `pk_m` - Moderator Public Key
    /// * `pk_r` - Recipient Public Key (ClientPublicKey)
    /// * `k_f` - Franking Key
    /// * `r` - Random Scalar for Pedersen Commitment
    /// * `m` - Message to be Franked
    /// * `t_msg` - Message Timestamp
    /// * `ctx` - Session Context
    ///
    /// # Returns
    /// * `FrankData` - contains the Franking AD
    pub fn frank(
        &self,
        pk_m: &ModeratorPublicKey,
        pk_r: &ClientPublicKey,
        k_f: &FrankingKey,
        r: &Scalar,
        m: &[u8],
        t_msg: u64,
        ctx: &SessionContext,
    ) -> EMFFrankingData {
        // Generate Random Scalar Alpha
        let alpha = Scalar::random(&mut OsRng);

        // Compute R (pk_r)^alpha
        let r_point = (alpha * pk_r).compress();

        // Compute E_r = g^alpha
        let e_r = RistrettoPoint::mul_base(&alpha).compress();

        // Compute MAC Tag t
        let (tag, h_m) = mac::tag(k_f, m, &ctx.id, t_msg);

        // Encrypt tag using ElGamal
        let (enc_tag, r_enc) = emf::encrypt(&pk_m.pk_enc, &tag);

        // Compute proof pi
        let pi = zk_mac_dlog_prove(
            &r_point,
            k_f,
            r,
            &r_enc,
            &pk_m.pk_enc,
            &enc_tag,
            m,
            &h_m,
            t_msg,
            ctx,
        );

        // Return Franking Data
        EMFFrankingData {
            r_point,
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
    /// * `ad` - Franking Data
    /// * `m` - Message to be Verified
    /// * `t_msg` - Message Timestamp
    /// * `ctx` - Session Context
    ///
    /// # Returns
    /// * `bool` - indicating validity (true) or invalidity (false)
    pub fn verify(
        &self,
        pk_m: &ModeratorPublicKey,
        ad: &EMFFrankingData,
        m: &[u8],
        t_msg: u64,
        ctx: &SessionContext,
    ) -> Result<ElGamalCiphertext, Error> {
        let EMFFrankingData {
            r_point,
            e_r,
            enc_tag,
            pi,
        } = ad;

        // Decompress points for computation
        let decompressed_e_r = e_r.decompress().unwrap();

        let recomputed_r = (self.sk * decompressed_e_r).compress();
        let is_r_valid = recomputed_r == *r_point;
        let is_t_valid = t_msg < ctx.t_expiry;
        let is_pi_valid = zk_mac_dlog_verify(r_point, &pk_m.pk_enc, enc_tag, m, t_msg, ctx, pi);

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

    use signature::Verifier;

    use super::*;

    #[test]
    fn test_issue_cert_generates_valid_sig() {
        let moderator = Moderator::new();
        let client = Client::new();

        let t_expiry = compute_timestamp(WEEK_OFFSET);
        let (_k_f, _r, k_pub, sig) = moderator.issue_cert(&client.id, t_expiry);

        let ctx = SessionContext {
            id: client.id,
            k_pub: k_pub.decompress().unwrap(),
            t_expiry,
        };

        let data: [u8; REGISTRATION_SERIALIZATION_LEN] = serialize_registration(&ctx);

        assert!(moderator.pk.pk_sig.verify(&data, &sig).is_ok());
    }

    #[test]
    fn test_issue_cert_generates_valid_keys() {
        let moderator = Moderator::new();
        let client = Client::new();

        let t_expiry = compute_timestamp(WEEK_OFFSET);
        let (k_f, r, k_pub, _sig) = moderator.issue_cert(&client.id, t_expiry);

        let (x0, x1) = k_f;

        assert_eq!(
            compute_pedersen_multicomm(&x0, &x1, &r),
            k_pub.decompress().unwrap(),
            "Franking key does not match public key"
        );
    }
}
