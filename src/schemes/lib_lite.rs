use crate::toolbox::lib_common::*;
use crate::toolbox::lib_lite_zkp::*;
use crate::toolbox::lib_mac_ggm as mac;
use crate::toolbox::lib_prf as prf;
use crate::toolbox::lib_prf::PRFKey;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::{RistrettoPoint, Scalar};
use ed25519_dalek::Signature;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::io::Error;

// Structs
pub struct LiteFrankingData {
    pub r_point: CompressedRistretto, // Ristretto Point R
    pub e_r: CompressedRistretto,     // Ephemeral Ristretto Point E_r
    pub tag: CompressedRistretto,     // MAC Tag t
    pub pi: MacOrDlogZKProof,         // ZK Proof of Knowledge of MAC Tag
}

// Type Definitions
pub struct ModeratorSecretKey {
    k_prf: PRFKey,
    sk_sig: SigningKey,
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
pub fn moderator_keygen() -> (VerifyingKey, ModeratorSecretKey) {
    let k_prf = prf::keygen();
    let (signing_key, verifying_key) = moderator_sig_keygen();

    let secret_key = ModeratorSecretKey {
        k_prf,
        sk_sig: signing_key,
    };

    (verifying_key, secret_key)
}

// Moderator Properties
pub struct Moderator {
    pub pk: VerifyingKey,   // Moderator Public Key
    sk: ModeratorSecretKey, // Moderator Secret Key
}

// Moderator Implementation
#[allow(clippy::new_without_default)] // avoid default since keygen is expensive
impl Moderator {
    // KeyGenMod(1^lambda)
    pub fn new() -> Self {
        let (verifying_key, secret_key) = moderator_keygen();

        Moderator {
            pk: verifying_key,
            sk: secret_key,
        }
    }

    // Issue Cert Function
    /// Issues a certificate to a user from the moderator.
    ///
    /// # Arguments
    /// * `sk_M` - Moderator Secret Key
    /// * `id` - User Identifier
    /// * `t_expiry` - Signature Expiry Time
    /// *
    /// # Returns
    /// * `k_f` - Franking Key
    /// * `r` - randomness for Pedersen commitment
    /// * `k_pub` - Public Key
    /// * `sig` - Moderator Signature on User Registration
    pub fn issue_cert(
        &self,
        id: &ClientId,
        t_expiry: u64,
    ) -> (FrankingKey, Scalar, CompressedPublicFrankingKey, Signature) {
        issue_cert(&self.sk.k_prf, &self.sk.sk_sig, id, t_expiry)
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
        m: &[u8],
        t_msg: u64,
        ctx: &SessionContext,
        tag: &CompressedRistretto,
    ) -> bool {
        let is_time_valid = t_msg < ctx.t_expiry;
        let is_tag_valid = mac::verify(k_f, m, &ctx.id, t_msg, tag);

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
        pk_m: &VerifyingKey,
        k_f: &FrankingKey,
        r: &Scalar,
        ctx: &CompressedSessionContext,
        sig: &Signature,
    ) -> bool {
        session_init(pk_m, k_f, r, ctx, sig)
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
    /// * `pk_r` - Recipient Public Key (ClientPublicKey)
    /// * `k_f` - Franking Key
    /// * `r` - Random Scalar for Pedersen Commitment
    /// * `m` - Message to be Franked
    /// * `t_msg` - Message Timestamp
    ///
    /// # Returns
    /// * `FrankData` - contains the Franking AD
    pub fn frank(
        &self,
        pk_r: &ClientPublicKey,
        k_f: &FrankingKey,
        r: &Scalar,
        m: &[u8],
        t_msg: u64,
        ctx: &SessionContext,
    ) -> LiteFrankingData {
        // Generate Random Scalar Alpha
        let alpha = Scalar::random(&mut OsRng);

        // Compute R (pk_r)^alpha
        let r_point = (alpha * pk_r).compress();

        // Compute E_r = g^alpha
        let e_r = RistrettoPoint::mul_base(&alpha).compress();

        // Compute MAC Tag t
        let (tag, h_m) = mac::tag(k_f, m, &ctx.id, t_msg);

        // Compute proof pi
        let pi = zk_mac_dlog_prove(&r_point, k_f, r, &tag, m, &h_m, t_msg, ctx);

        // Return Franking Data
        LiteFrankingData {
            r_point,
            e_r,
            tag,
            pi,
        }
    }

    // Verify Function
    /// Verifies that a message has been properly franked.
    ///
    /// # Arguments
    /// * `m` - Message to be Verified
    /// * `ad` - Franking Data
    /// * `t_msg` - Message Timestamp
    /// * `ctx` - Session Context
    ///
    /// # Returns
    /// * `bool` - indicating validity (true) or invalidity (false)
    pub fn verify(
        &self,
        ad: &LiteFrankingData,
        m: &[u8],
        t_msg: u64,
        ctx: &SessionContext,
    ) -> Result<CompressedRistretto, Error> {
        let LiteFrankingData {
            r_point,
            e_r,
            tag,
            pi,
        } = ad;

        // Decompress points for computation
        let decompressed_r = r_point.decompress().unwrap();
        let decompressed_e_r = e_r.decompress().unwrap();

        // Reject R/E_R identity elements
        if decompressed_r.is_identity() || decompressed_e_r.is_identity() {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "R and E_R must not be the identity element.",
            ));
        }

        let recomputed_r = (self.sk * decompressed_e_r).compress();
        let is_r_valid = recomputed_r == *r_point;
        let is_t_valid = t_msg < ctx.t_expiry;
        let is_pi_valid = zk_mac_dlog_verify(r_point, tag, m, t_msg, ctx, pi);

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

        assert!(moderator.pk.verify(&data, &sig).is_ok());
    }

    #[test]
    fn test_issue_cert_generates_valid_keys() {
        let moderator = Moderator::new();
        let client = Client::new();

        let t_expiry = compute_timestamp(WEEK_OFFSET);
        let (k_f, r, k_pub, _sig) = moderator.issue_cert(&client.id, t_expiry);

        let (x0, x1) = k_f;

        assert_eq!(
            (x0 * (*G0)) + (x1 * (*G1)) + (r * (*H)),
            k_pub.decompress().unwrap()
        );
    }
}
