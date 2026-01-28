use curve25519_dalek::RistrettoPoint;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::distributions::{Alphanumeric, DistString};

use crate::schemes::lib_basic::*;
use crate::toolbox::lib_common::*;

// Initialize Moderator and Client Only
pub fn test_init_moderator_client() -> (Moderator, Client) {
    let moderator = Moderator::new();
    let client = Client::new();

    (moderator, client)
}

// Set Up Moderator, Sender, and Receiver and Session Keys
pub fn test_init_full_session_data(
    t_expiry: u64,
) -> (Moderator, Client, Client, FrankingKey, PublicKey, Signature) {
    let moderator = Moderator::new();
    let sender = Client::new();
    let receiver = Client::new();

    let (k_f, k_pub, sig) = moderator.register_user(&sender.id, t_expiry);

    (moderator, sender, receiver, k_f, k_pub, sig)
}

// Initialize Messages of Varying Sizes
pub fn test_basic_init_messages() -> Vec<String> {
    let mut ms: Vec<String> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE {
        ms.push(Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size));
    }

    ms
}

// Initialize Messages of Varying Sizes with Franking Data
pub fn test_init_messages_with_franking_data(
    sender: &Client,
    pk_r: &RistrettoPoint,
    k_f: &FrankingKey,
    k_pub: &PublicKey,
    t_msg: u64,
) -> (Vec<String>, Vec<FrankingData>) {
    let ms = test_basic_init_messages();

    // Generate Franking Data for Each Message
    let mut fds: Vec<FrankingData> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for m in &ms {
        fds.push(test_frank_message(
            sender,
            pk_r,
            k_f,
            k_pub,
            m.as_bytes(),
            t_msg,
        ));
    }

    (ms, fds)
}

// Moderator: Register User
pub fn test_register_user(
    moderator: &Moderator,
    client: &Client,
    t_expiry: u64,
) -> (FrankingKey, PublicKey, Signature) {
    moderator.register_user(&client.id, t_expiry)
}

// Moderator: Moderate Report
pub fn test_moderate_report(
    moderator: &Moderator,
    k_f: &FrankingKey,
    t_expiry: u64,
    m: &[u8],
    ctx: MessageContext,
    tag: &RistrettoPoint,
) -> bool {
    moderator.moderate(k_f, t_expiry, m, ctx, tag)
}

// Client: Session Init
pub fn test_basic_session_init(
    pk_m: &VerifyingKey,
    client: &Client,
    k_f: &FrankingKey,
    k_pub: &PublicKey,
    t_expiry: u64,
    sig: &Signature,
) -> bool {
    client.session_init(pk_m, k_f, k_pub, t_expiry, sig)
}

// Client: Accept Session
pub fn test_receiver_accept_session(
    pk_m: &VerifyingKey,
    sender_id: &[u8; 32],
    receiver: &Client,
    k_pub: &PublicKey,
    t_expiry: u64,
    sig: &Signature,
) -> bool {
    receiver.accept_session(pk_m, sender_id, k_pub, t_expiry, sig)
}

// Client: Frank Message
pub fn test_frank_message(
    sender: &Client,
    pk_r: &RistrettoPoint,
    k_f: &FrankingKey,
    k_pub: &PublicKey,
    m: &[u8],
    t_msg: u64,
) -> FrankingData {
    let ctx = (sender.id, t_msg);
    sender.frank(pk_r, k_f, k_pub, m, ctx)
}

// Client: Verify Message
pub fn test_verify_message(
    receiver: &Client,
    ad: &FrankingData,
    m: &[u8],
    ctx: MessageContext,
    t_expiry: u64,
) -> RistrettoPoint {
    receiver.verify(&receiver.pk, ad, m, ctx, t_expiry)
}
