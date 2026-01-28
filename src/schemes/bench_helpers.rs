use rand::distributions::{Alphanumeric, DistString};

use crate::schemes::lib_basic::*;
use crate::toolbox::lib_common::*;

// Set Up Moderator, Sender, and Receiver
pub fn test_session_set_up() -> (Moderator, Client, Client) {
    let moderator = Moderator::new();
    let sender = Client::new();
    let receiver = Client::new();

    (moderator, sender, receiver)
}

// Set Up Session
pub fn test_register_user(
    moderator: &Moderator,
    client: &Client,
    t_expiry: u64,
) -> (FrankingKey, PublicKey) {
    // Register User
    let (k_f, k_pub, _sig) = moderator.register_user(&client.id, t_expiry);

    (k_f, k_pub)
}

// Setup Messages
pub fn test_basic_init_messages() -> Vec<String> {
    let mut ms: Vec<String> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE {
        ms.push(Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size));
    }

    ms
}

// Frank Message
pub fn test_frank_message(
    sender: &Client,
    receiver: &Client,
    k_f: &FrankingKey,
    k_pub: &PublicKey,
    m: &[u8],
    t_msg: u64,
) -> FrankingData {
    let ctx = (sender.id, t_msg);
    sender.frank(&receiver.pk, k_f, k_pub, m, ctx)
}
