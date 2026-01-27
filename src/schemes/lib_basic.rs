use crate::toolbox::lib_common::*;
use crate::toolbox::lib_mac_ggm::*;
use crate::toolbox::lib_zkpok::*;

// Ristretto
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::{RistrettoPoint, Scalar};

use ed25519_dalek::Signature;
// Signature
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
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
        &self,
        k_f: &FrankingKey,
        t_expiry: u64,
        m: &[u8],
        ctx: MessageContext,
        tag: &RistrettoPoint,
    ) -> bool {
        // Unpack context
        let (id, t_msg) = ctx;

        let is_time_valid = t_msg < t_expiry;
        let is_sig_valid = mac_verify(k_f, &id, m, t_msg, tag);

        is_time_valid && is_sig_valid
    }
}

// Client Properties
pub struct Client {
    pub id: [u8; 32],       // User Identifier
    pub pk: RistrettoPoint, // User Public Key (g^sk)
    _sk: Scalar,            // User Secret Key
}

// Client Implementation
#[allow(clippy::new_without_default)] // avoid default since keygen is expensive
impl Client {
    // KeyGenUser(1^lambda)
    pub fn new() -> Self {
        let sk = user_keygen();
        let pk = &sk * G;
        Client {
            pk,
            _sk: sk,
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
        k_pub: &PublicKey,
        t_expiry: u64,
        sig: &Signature,
    ) -> bool {
        // Verify FrankingKey and PublicKey
        let computed_k_pub = compute_public_key(k_f);
        let is_k_pub_valid = k_pub == &computed_k_pub;

        // Serialize message registration data and verify signature
        let msg: [u8; REGISTRATION_SERIALIZATION_LEN] =
            serialize_registration(&self.id, k_pub, t_expiry);
        let is_sig_valid = pk_m.verify(&msg, sig).is_ok();

        is_k_pub_valid && is_sig_valid
    }

    // AcceptSession Function
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
        &self,
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
        &self,
        // pk_m: &VerifyingKey,
        pk_r: &RistrettoPoint,
        k_f: &FrankingKey,
        k_pub: &PublicKey,
        m: &[u8],
        ctx: MessageContext,
    ) -> FrankingData {
        // Unpack context
        let (id, t_msg) = ctx;

        // Generate Random Scalar Alpha
        let alpha = Scalar::random(&mut OsRng);

        // Compute R (pk_r)^alpha
        let r = alpha * pk_r;

        // Compute E_r = g^alpha
        let e_r = &alpha * G;

        // Compute MAC Tag t
        let tag = mac_tag(k_f, &id, m, t_msg);

        // Compute proof pi
        let pi = zk_prove(&r, k_f, k_pub, &tag, m, ctx);

        // Return Franking Data
        FrankingData {
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
        &self,
        // pk_m: &VerifyingKey,
        pk_r: &RistrettoPoint,
        sk_r: &Scalar,
        ad: &FrankingData,
        m: &[u8],
        ctx: MessageContext,
        t_expiry: u64,
    ) -> RistrettoPoint {
        // Unpack context
        let (_id, t_msg) = ctx;

        let FrankingData {
            k_pub,
            r_point,
            e_r,
            tag,
            pi,
        } = ad;

        let recomputed_r = sk_r * e_r;
        let is_r_valid = &recomputed_r == r_point;
        let is_t_valid = t_msg < t_expiry;
        let is_pi_valid = zk_verify(r_point, k_pub, pk_r, tag, m, ctx, pi);

        assert!(is_r_valid && is_t_valid && is_pi_valid);

        *tag
    }
}

// Test Functions

// Set Up Moderator
pub fn test_moderator_setup() -> Moderator {
    Moderator::new()
}

// Set up Multiple Moderators
pub fn test_basic_init_moderators(num_moderators: usize) -> Vec<Moderator> {
    let mut moderators: Vec<Moderator> = Vec::with_capacity(num_moderators);
    for _ in 0..num_moderators {
        moderators.push(test_moderator_setup());
    }
    moderators
}

// Set Up Client
pub fn test_client_setup() -> Client {
    Client::new()
}

// Set Up Multiple Clients
pub fn test_basic_init_clients(num_clients: usize) -> Vec<Client> {
    let mut clients: Vec<Client> = Vec::with_capacity(num_clients);
    for _ in 0..num_clients {
        clients.push(test_client_setup());
    }
    clients
}

// Set Up Session
pub fn test_basic_set_up_session(
    moderator: &Moderator,
    sender: &Client,
    receiver: &Client,
    t_expiry: u64,
) -> (FrankingKey, PublicKey) {
    // Register User
    let (k_f, k_pub, sig) = moderator.register_user(&sender.id, t_expiry);

    // Initialize Session
    let is_session_valid = sender.session_init(&moderator.pk, &k_f, &k_pub, t_expiry, &sig);
    assert!(is_session_valid, "Session initialization failed");

    // Accept Session by Receiver
    let is_session_accepted =
        receiver.accept_session(&moderator.pk, &sender.id, &k_pub, t_expiry, &sig);
    assert!(is_session_accepted, "Session acceptance failed");

    (k_f, k_pub)
}

// Setup Messages
pub fn test_basic_init_messages(num_clients: usize, msg_size: usize) -> Vec<String> {
    // Prepare messages
    let mut ms: Vec<String> = Vec::with_capacity(num_clients);
    for _i in 0..num_clients {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }
    ms
}

// Frank Message
pub fn test_frank_message(
    client: &Client,
    receiver: &Client,
    k_f: &FrankingKey,
    k_pub: &PublicKey,
    m: &[u8],
    t_msg: u64,
) -> FrankingData {
    let ctx = (client.id, t_msg);
    client.frank(&receiver.pk, k_f, k_pub, m, ctx)
}
