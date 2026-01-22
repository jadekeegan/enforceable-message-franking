use crate::lib_common::*;
use crate::lib_mac_ggm::*;

// Ristretto
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;

// Signature
use ed25519_dalek::{SigningKey, VerifyingKey};

// Moderator Properties
pub struct Moderator {
  sk: SigningKey,   // Moderator Secret Key
}

// TODO: ZK.Prove, ZK.Verify
// Chapter 19 Boneh Shoup for Proof, 19.5.3

// Moderator Implementation
impl Moderator {
  // KeyGenMod(1^lambda)
  pub fn new() -> Self {
    let signing_key = moderator_keygen();
    Moderator {
      sk: signing_key,
    }
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
  pub fn register_user(&self, id: &Vec<u8>, t_expiry: u64) -> ([u8; 64], RistrettoPoint, Vec<u8>) {
      let k_f = mac_keygen();
      let (x_0, x_1) = k_f;

      let g_0: RistrettoPoint = &x_0 * &RISTRETTO_BASEPOINT_TABLE;
      let g_1: RistrettoPoint = &x_1 * &RISTRETTO_BASEPOINT_TABLE;

      let k_pub = (g_0, g_1);

      let mut msg: Vec<u8> = Vec::new();
      // Q: Recommended serialization method?
      // serialize each component separately and put into allocated array with fixed size

      unimplemented!()
  }

  // TODO: Moderate Function
  /// Verifies that a message has been properly franked.
  /// 
  /// # Arguments
  /// * `k_f` - Franking Key
  /// * `t_expiry` - Signature Expiry Time
  /// * `m` - Message to be Verified
  /// * `ctx` - Message Context
  /// * `T` - Mac Tag
  ///
  /// # Returns
  /// * `bool` - indicating validity (true) or invalidity (false)

}


// TODO: Client Properties


// Client Implementation
impl Client {
  // KeyGenUser(1^lambda)
  pub fn new() -> Self {
        Client {}
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

}