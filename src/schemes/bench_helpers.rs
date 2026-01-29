use curve25519_dalek::RistrettoPoint;
use ed25519_dalek::Signature;
use rand::distributions::{Alphanumeric, DistString};

use crate::schemes::lib_basic::*;
use crate::toolbox::lib_common::*;
use crate::toolbox::lib_mac_dlog_zk_proof as zkp;

pub const MSG_SIZE_SCALE: [usize; 7] = [256, 512, 1024, 2048, 4096, 8192, 65536];

// Initialize Moderator and Client Only
pub fn test_init_moderator_client() -> (Moderator, Client) {
    let moderator = Moderator::new();
    let client = Client::new();

    (moderator, client)
}

// Set Up Client with Session Keys
pub fn test_init_client_with_keys(t_expiry: u64) -> (Client, FrankingKey, PublicKey) {
    let moderator = Moderator::new();
    let client = Client::new();

    let (k_f, k_pub, _sig) = moderator.register_user(&client.id, t_expiry);
    (client, k_f, k_pub)
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
        fds.push(sender.frank(pk_r, k_f, k_pub, m.as_bytes(), (sender.id, t_msg)));
    }

    (ms, fds)
}

// Initialize Messages of Varying Sizes with Franking Data and Proof
pub fn test_init_messages_with_franking_data_and_proof(
    sender: &Client,
    pk_r: &RistrettoPoint,
    k_f: &FrankingKey,
    k_pub: &PublicKey,
    t_msg: u64,
) -> (Vec<String>, Vec<FrankingData>, Vec<zkp::MacOrDlogZKProof>) {
    let ms = test_basic_init_messages();

    // Generate Franking Data with Proof for Each Message
    let mut fds: Vec<FrankingData> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    let mut pis: Vec<zkp::MacOrDlogZKProof> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for m in &ms {
        let fd = sender.frank(pk_r, k_f, k_pub, m.as_bytes(), (sender.id, t_msg));
        pis.push(zkp::zk_mac_dlog_prove(
            &fd.r_point,
            k_f,
            k_pub,
            &fd.tag,
            m.as_bytes(),
            (sender.id, t_msg),
        ));
        fds.push(fd);
    }

    (ms, fds, pis)
}
