use crate::schemes::lib_basic as basic;
use crate::schemes::lib_elgamal as elgamal;
use crate::schemes::lib_elgamal::ModeratorPublicKey;
use crate::toolbox::lib_common::*;
use crate::toolbox::lib_elgamal_enc as elgamal_enc;
use crate::toolbox::lib_mac_ggm as mac_ggm;
use curve25519_dalek::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::Signature;
use rand::distributions::{Alphanumeric, DistString};

pub const MSG_SIZE_SCALE: [usize; 7] = [100, 500, 1_000, 5_000, 10_000, 50_000, 100_000];

// Basic Scheme Bench Helpers

// Initialize Moderator and Client Only
pub fn test_basic_init_moderator_client() -> (basic::Moderator, basic::Client) {
    let moderator = basic::Moderator::new();
    let client = basic::Client::new();

    (moderator, client)
}

// Set Up Client with Session Keys
pub fn test_basic_init_client_with_keys(
    t_expiry: u64,
) -> (basic::Client, FrankingKey, Scalar, PublicFrankingKey) {
    let moderator = basic::Moderator::new();
    let client = basic::Client::new();

    let (k_f, r, k_pub, _sig) = moderator.issue_cert(&client.id, t_expiry);
    let decompressed_k_pub = k_pub.decompress().unwrap();

    (client, k_f, r, decompressed_k_pub)
}

// Set Up Moderator, Sender, and Receiver and Session Keys
pub fn test_basic_init_full_session_data(
    t_expiry: u64,
) -> (
    basic::Moderator,
    basic::Client,
    basic::Client,
    FrankingKey,
    Scalar,
    SessionContext,
    Signature,
) {
    let moderator = basic::Moderator::new(); // KeyGenMod
    let sender = basic::Client::new(); // KeyGenUser
    let receiver = basic::Client::new();

    // Register Sender for Keys/Sig
    let (k_f, r, k_pub, sig) = moderator.issue_cert(&sender.id, t_expiry);

    let ctx = SessionContext {
        id: sender.id,
        k_pub: k_pub.decompress().unwrap(),
        t_expiry,
    };

    (moderator, sender, receiver, k_f, r, ctx, sig)
}

// Initialize Message of Given Size
pub fn test_init_message(msg_size: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size)
}

// Initialize Messages of Varying Sizes
pub fn test_init_messages() -> Vec<String> {
    let mut ms: Vec<String> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE {
        ms.push(Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size));
    }

    ms
}

// Initialize Messages of Varying Sizes with Tags
pub fn test_basic_init_messages_with_tags(
    k_f: &FrankingKey,
    client: &basic::Client,
    t_msg: u64,
) -> (Vec<String>, Vec<CompressedRistretto>) {
    let ms = test_init_messages();

    // Generate Tags for Each Message
    let mut tags: Vec<CompressedRistretto> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for m in &ms {
        tags.push(mac_ggm::tag(k_f, m.as_bytes(), &client.id, t_msg));
    }

    (ms, tags)
}

// Initialize Messages of Varying Sizes with Franking Data
pub fn test_basic_init_messages_with_franking_data(
    sender: &basic::Client,
    pk_r: &ClientPublicKey,
    k_f: &FrankingKey,
    r: &Scalar,
    k_pub: &PublicFrankingKey,
    t_msg: u64,
) -> (Vec<String>, Vec<basic::BasicFrankingData>) {
    let ms = test_init_messages();

    let ctx = SessionContext {
        id: sender.id,
        k_pub: *k_pub,
        t_expiry: 1_000_000u64,
    };

    // Generate Franking Data for Each Message
    let mut fds: Vec<basic::BasicFrankingData> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for m in &ms {
        fds.push(sender.frank(pk_r, k_f, r, m.as_bytes(), t_msg, &ctx));
    }

    (ms, fds)
}

// ElGamal Scheme Bench Helpers

// Initialize Moderator and Client Only
pub fn test_elgamal_init_moderator_client() -> (elgamal::Moderator, elgamal::Client) {
    let moderator = elgamal::Moderator::new();
    let client = elgamal::Client::new();

    (moderator, client)
}

// Set Up Client with Session Keys
pub fn test_elgamal_init_client_with_keys(
    t_expiry: u64,
) -> (elgamal::Client, FrankingKey, Scalar, PublicFrankingKey) {
    let moderator = elgamal::Moderator::new();
    let client = elgamal::Client::new();

    let (k_f, r, k_pub, _sig) = moderator.issue_cert(&client.id, t_expiry);
    let decompressed_k_pub = k_pub.decompress().unwrap();

    (client, k_f, r, decompressed_k_pub)
}

// Set Up Moderator, Sender, and Receiver and Session Keys
pub fn test_elgamal_init_full_session_data(
    t_expiry: u64,
) -> (
    elgamal::Moderator,
    elgamal::Client,
    elgamal::Client,
    FrankingKey,
    Scalar,
    SessionContext,
    Signature,
) {
    let moderator = elgamal::Moderator::new(); // KeyGenMod
    let sender = elgamal::Client::new(); // KeyGenUser
    let receiver = elgamal::Client::new();

    // Register Sender for Keys/Sig
    let (k_f, r, k_pub, sig) = moderator.issue_cert(&sender.id, t_expiry);

    let ctx = SessionContext {
        id: sender.id,
        k_pub: k_pub.decompress().unwrap(),
        t_expiry,
    };

    (moderator, sender, receiver, k_f, r, ctx, sig)
}

// Initialize Messages of Varying Sizes with Tags
pub fn test_elgamal_init_messages_with_tags(
    k_f: &FrankingKey,
    client: &elgamal::Client,
    t_msg: u64,
) -> (Vec<String>, Vec<elgamal_enc::ElGamalCiphertext>) {
    let ms = test_init_messages();

    // Generate Tags for Each Message
    let mut tags: Vec<elgamal_enc::ElGamalCiphertext> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for m in &ms {
        let tag = mac_ggm::tag(k_f, m.as_bytes(), &client.id, t_msg);
        tags.push(elgamal_enc::encrypt(&client.pk, &tag).0);
    }

    (ms, tags)
}

// Initialize Messages of Varying Sizes with Franking Data
pub fn test_elgamal_init_messages_with_franking_data(
    sender: &elgamal::Client,
    pk_m: &ModeratorPublicKey,
    pk_r: &ClientPublicKey,
    k_f: &FrankingKey,
    r: &Scalar,
    k_pub: &PublicFrankingKey,
    t_msg: u64,
) -> (Vec<String>, Vec<elgamal::ElGamalFrankingData>) {
    let ms = test_init_messages();

    let ctx = SessionContext {
        id: sender.id,
        k_pub: *k_pub,
        t_expiry: 1_000_000u64,
    };

    // Generate Franking Data for Each Message
    let mut fds: Vec<elgamal::ElGamalFrankingData> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for m in &ms {
        fds.push(sender.frank(pk_m, pk_r, k_f, r, m.as_bytes(), t_msg, &ctx));
    }

    (ms, fds)
}
