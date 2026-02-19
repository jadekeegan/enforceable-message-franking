use crate::schemes::lib_emf as emf;
use crate::schemes::lib_emf::ModeratorPublicKey;
use crate::schemes::lib_lite as lite;
use crate::toolbox::lib_common::*;
use crate::toolbox::lib_emf_enc as emf_enc;
use crate::toolbox::lib_mac_ggm as mac_ggm;
use curve25519_dalek::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::Signature;
use rand::distributions::{Alphanumeric, DistString};

pub const MSG_SIZE_SCALE: [usize; 7] = [100, 500, 1_000, 5_000, 10_000, 50_000, 100_000];

// Lite Scheme Bench Helpers

// Initialize Moderator and Client Only
pub fn test_lite_init_moderator_client() -> (lite::Moderator, lite::Client) {
    let moderator = lite::Moderator::new();
    let client = lite::Client::new();

    (moderator, client)
}

// Set Up Client with Session Keys
pub fn test_lite_init_client_with_keys(
    t_expiry: u64,
) -> (lite::Client, FrankingKey, Scalar, PublicFrankingKey) {
    let moderator = lite::Moderator::new();
    let client = lite::Client::new();

    let (k_f, r, k_pub, _sig) = moderator.issue_cert(&client.id, t_expiry);
    let decompressed_k_pub = k_pub.decompress().unwrap();

    (client, k_f, r, decompressed_k_pub)
}

// Set Up Moderator, Sender, and Receiver and Session Keys
pub fn test_lite_init_full_session_data(
    t_expiry: u64,
) -> (
    lite::Moderator,
    lite::Client,
    lite::Client,
    FrankingKey,
    Scalar,
    SessionContext,
    Signature,
) {
    let moderator = lite::Moderator::new(); // KeyGenMod
    let sender = lite::Client::new(); // KeyGenUser
    let receiver = lite::Client::new();

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
pub fn test_lite_init_messages_with_tags(
    k_f: &FrankingKey,
    client: &lite::Client,
    t_msg: u64,
) -> (Vec<String>, Vec<CompressedRistretto>) {
    let ms = test_init_messages();

    // Generate Tags for Each Message
    let mut tags: Vec<CompressedRistretto> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for m in &ms {
        tags.push(mac_ggm::tag(k_f, m.as_bytes(), &client.id, t_msg).0);
    }

    (ms, tags)
}

// Initialize Messages of Varying Sizes with Franking Data
pub fn test_lite_init_messages_with_franking_data(
    sender: &lite::Client,
    pk_r: &ClientPublicKey,
    k_f: &FrankingKey,
    r: &Scalar,
    k_pub: &PublicFrankingKey,
    t_msg: u64,
) -> (Vec<String>, Vec<lite::LiteFrankingData>) {
    let ms = test_init_messages();

    let ctx = SessionContext {
        id: sender.id,
        k_pub: *k_pub,
        t_expiry: 1_000_000u64,
    };

    // Generate Franking Data for Each Message
    let mut fds: Vec<lite::LiteFrankingData> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for m in &ms {
        fds.push(sender.frank(pk_r, k_f, r, m.as_bytes(), t_msg, &ctx));
    }

    (ms, fds)
}

// EMF Scheme Bench Helpers

// Initialize Moderator and Client Only
pub fn test_emf_init_moderator_client() -> (emf::Moderator, emf::Client) {
    let moderator = emf::Moderator::new();
    let client = emf::Client::new();

    (moderator, client)
}

// Set Up Client with Session Keys
pub fn test_emf_init_client_with_keys(
    t_expiry: u64,
) -> (emf::Client, FrankingKey, Scalar, PublicFrankingKey) {
    let moderator = emf::Moderator::new();
    let client = emf::Client::new();

    let (k_f, r, k_pub, _sig) = moderator.issue_cert(&client.id, t_expiry);
    let decompressed_k_pub = k_pub.decompress().unwrap();

    (client, k_f, r, decompressed_k_pub)
}

// Set Up Moderator, Sender, and Receiver and Session Keys
pub fn test_emf_init_full_session_data(
    t_expiry: u64,
) -> (
    emf::Moderator,
    emf::Client,
    emf::Client,
    FrankingKey,
    Scalar,
    SessionContext,
    Signature,
) {
    let moderator = emf::Moderator::new(); // KeyGenMod
    let sender = emf::Client::new(); // KeyGenUser
    let receiver = emf::Client::new();

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
pub fn test_emf_init_messages_with_tags(
    k_f: &FrankingKey,
    client: &emf::Client,
    t_msg: u64,
) -> (Vec<String>, Vec<emf_enc::ElGamalCiphertext>) {
    let ms = test_init_messages();

    // Generate Tags for Each Message
    let mut tags: Vec<emf_enc::ElGamalCiphertext> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for m in &ms {
        let (tag, _h_m) = mac_ggm::tag(k_f, m.as_bytes(), &client.id, t_msg);
        tags.push(emf_enc::encrypt(&client.pk, &tag).0);
    }

    (ms, tags)
}

// Initialize Messages of Varying Sizes with Franking Data
pub fn test_emf_init_messages_with_franking_data(
    sender: &emf::Client,
    pk_m: &ModeratorPublicKey,
    pk_r: &ClientPublicKey,
    k_f: &FrankingKey,
    r: &Scalar,
    k_pub: &PublicFrankingKey,
    t_msg: u64,
) -> (Vec<String>, Vec<emf::EMFFrankingData>) {
    let ms = test_init_messages();

    let ctx = SessionContext {
        id: sender.id,
        k_pub: *k_pub,
        t_expiry: 1_000_000u64,
    };

    // Generate Franking Data for Each Message
    let mut fds: Vec<emf::EMFFrankingData> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for m in &ms {
        fds.push(sender.frank(pk_m, pk_r, k_f, r, m.as_bytes(), t_msg, &ctx));
    }

    (ms, fds)
}
