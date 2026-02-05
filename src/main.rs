use std::mem;

use curve25519_dalek::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::Signature;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

use clap::Parser;

// Macro for Printing Out Status Messages for Logs
/// Usage: status!(condition, "Success Message", "Failure Message");
macro_rules! status {
    ($cond:expr, $success:expr, $failure:expr) => {
        if $cond {
            println!("{}", $success);
        } else {
            println!("{}", $failure);
        }
    };
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
struct Args {
    #[arg(long, default_value_t = false)]
    basic: bool,

    #[arg(long, default_value_t = false)]
    elgamal: bool,

    #[arg(long, default_value_t = 100)]
    msg_size: usize,

    #[arg(long, default_value_t = false)]
    print_costs: bool,
}

fn main() {
    let args = Args::parse();

    if args.basic {
        test_basic(args.msg_size, args.print_costs);
    }

    if args.elgamal {
        test_elgamal(args.msg_size, args.print_costs);
    }
}

// Test Basic Scheme
/// Completes all operations of the basic scheme for a certain message size, testing
/// franking and verification of one message between a sender and receiver.
///
/// # Arguments
/// * `msg_size` - Size of each message in bytes.
///
/// # Returns
/// * None
pub fn test_basic(msg_size: usize, print_costs: bool) {
    println!(
        "======================== Started Testing Basic Scheme with Message of Size {} ====================",
        msg_size
    );
    println!();

    // Initialize Session Data (sets up moderator, sender, receiver, and sender keys)
    println!("===> Initializing Moderator, Sender, Receiver, and Sender Keys");
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (moderator, sender, receiver, k_f, ctx, sig) = test_basic_init_full_session_data(t_expiry);

    if print_costs {
        // RegisterUser Communication Cost (Moderator to Client)
        // Moderator RegisterUser ---> Sender SessionInit
        // (1) Franking Key (k_f): 1 CompressedRistretto
        // (2) Franking Public Key (k_pub): 1 CompressedRistretto
        // (3) Signature (sig): 1 Signature
        let register_user_cost =
            mem::size_of::<CompressedRistretto>() * (1 + 1) + mem::size_of::<Signature>();
        println!(
            "Register User Communication Cost: {} (bytes)",
            register_user_cost
        );
    }

    // Sender Initializes Session
    println!("===> Sender Initializing Session");
    let session_init_success = sender.session_init(&moderator.pk, &k_f, &ctx, &sig);
    status!(
        session_init_success,
        "Sender session initialization successful.",
        "Sender session initialization failed."
    );

    if print_costs {
        // SessionInit Communication Cost (Sender to Receiver)
        // (1) Signature (sig): 1 Signature
        // (2) Session Context (ctx): 1 u64 (t_expiry), 1 ClientID, 1 FrankingPublicKey
        let session_init_cost = mem::size_of::<Signature>()
            + mem::size_of::<u64>()
            + mem::size_of::<ClientId>()
            + mem::size_of::<FrankingPublicKey>();
        println!(
            "Session Initialization Communication Cost: {} (bytes)",
            session_init_cost
        );
    }

    // Receiver Verifies and Accepts Sender Session
    println!("===> Receiver Accepting Sender Session");
    let accept_session_success = receiver.accept_session(&moderator.pk, &ctx, &sig);
    status!(
        accept_session_success,
        "Receiver successfully accepted sender session.",
        "Receiver rejected sender session."
    );

    if print_costs {
        // Session Storage Cost (Receiver)
        // Receiver stores session data for sender
        // (1) Session Context (ctx): 1 u64 (t_expiry), 1 ClientID, 1 FrankingPublicKey (2 CompressedRistretto)
        let session_storage_cost = mem::size_of::<u64>()
            + mem::size_of::<ClientId>()
            + mem::size_of::<CompressedRistretto>() * 2;
        println!("Session Storage Overhead: {} (bytes)", session_storage_cost);
    }

    // Initialize Message
    let m = test_init_message(msg_size);
    let t_msg = compute_timestamp(0);

    // Sender Frank Message
    println!("===> Sender Franking Message");
    let fd = sender.frank(&receiver.pk, &k_f, m.as_bytes(), t_msg, &ctx);

    if print_costs {
        // Communication Cost of Franking Data
        // (1) R (r_point): 1 CompressedRistretto
        // (2) Ephemeral R (e_r): 1 CompressedRistretto
        // (3) Tag (tag): 1 CompressedRistretto
        // (4) Proof (pi): 4 CompressedRistretto, 5 Scalars
        let frank_cost =
            mem::size_of::<CompressedRistretto>() * (1 + 1 + 1 + 4) + mem::size_of::<Scalar>() * 5;
        println!("Franking Communication Cost: {} (bytes)", frank_cost);
    }

    // Receiver Verifies Franking Data for Message
    println!("===> Receiver Verifying Franking Data for Message");
    let tag = receiver
        .verify(&fd, m.as_bytes(), t_msg, &ctx)
        .expect("Franking data verification failed.");

    if print_costs {
        // Communication Cost of Verification (Receiver to Moderator)
        // (1) Tag (tag): 1 CompressedRistretto
        let mod_cost = mem::size_of::<CompressedRistretto>();
        println!("Moderation Communication Cost: {} (bytes)", mod_cost);
    }

    // Moderator Verifies Franking Data for Message for Moderation
    println!("===> Moderator Verifying Franking Data for Message");
    let mod_verify_success = moderator.moderate(&k_f, m.as_bytes(), t_msg, &ctx, &tag);
    status!(
        mod_verify_success,
        "Moderator successfully verified franking data for message and tag.",
        "Moderator rejected franking data for message and tag."
    );

    if print_costs {
        // Storage Cost of Moderation (Moderator)
        // (1) id: 1 ClientID
        // (2) Franking Key (k_f): 2 Scalars
        // (3) Expiration Timestamp (t_expiry): 1 u64
        let mod_storage_cost =
            mem::size_of::<ClientId>() + mem::size_of::<Scalar>() * 2 + mem::size_of::<u64>();
        println!("Moderation Storage Cost: {} (bytes)", mod_storage_cost);
    }

    println!();
    println!(
        "======================== Completed Testing Basic Scheme with Message of Size {} ====================",
        msg_size
    );
    println!();
    println!();
}

// Test ElGamal Scheme
/// Completes all operations of the ElGamal scheme for a certain message size, testing
/// franking and verification of one message between a sender and receiver.
/// # Arguments
/// * `msg_size` - Size of each message in bytes.
///
/// # Returns
/// * None
pub fn test_elgamal(msg_size: usize, print_costs: bool) {
    println!(
        "======================== Started Testing ElGamal Scheme with Message of Size {} ====================",
        msg_size
    );
    println!();

    // Initialize Session Data (sets up moderator, sender, receiver, and sender keys)
    println!("===> Initializing Moderator, Sender, Receiver, and Sender Keys");
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (moderator, sender, receiver, k_f, ctx, sig) =
        test_elgamal_init_full_session_data(t_expiry);

    // Sender Initializes Session
    println!("===> Sender Initializing Session");
    let session_init_success = sender.session_init(&moderator.pk, &k_f, &ctx, &sig);
    status!(
        session_init_success,
        "Sender session initialization successful.",
        "Sender session initialization failed."
    );

    // Receiver Verifies and Accepts Sender Session
    println!("===> Receiver Accepting Sender Session");
    let accept_session_success = receiver.accept_session(&moderator.pk.pk_sig, &ctx, &sig);
    status!(
        accept_session_success,
        "Receiver successfully accepted sender session.",
        "Receiver rejected sender session."
    );

    if print_costs {
        // Session Storage Cost
        // (1) Franking Key (k_f): 1 Scalar
        // (2) Session Context (ctx): 1 u64 (t_expiry), 1 ClientID, 1 FrankingPublicKey
        let session_storage_cost = mem::size_of::<Scalar>()
            + mem::size_of::<u64>()
            + mem::size_of::<ClientId>()
            + mem::size_of::<FrankingPublicKey>();
        println!("Session Storage Overhead: {} (bytes)", session_storage_cost);
    }

    // Initialize Message
    let m = test_init_message(msg_size);
    let t_msg = compute_timestamp(0);

    // Sender Frank Message
    println!("===> Sender Franking Message");
    let fd = sender.frank(&moderator.pk, &receiver.pk, &k_f, m.as_bytes(), t_msg, &ctx);

    if print_costs {
        // Communication Cost of Franking Data
        // (1) R (r_point): 1 CompressedRistretto
        // (2) Ephemeral R (e_r): 1 CompressedRistretto
        // (3) Ciphertext (enc_tag): 2 CompressedRistretto
        // (4) Proof (pi): 5 CompressedRistretto, 6 Scalars
        let frank_cost =
            mem::size_of::<CompressedRistretto>() * (1 + 1 + 2 + 5) + mem::size_of::<Scalar>() * 6;
        println!("Franking Communication Cost: {} (bytes)", frank_cost);
    }

    // Receiver Verifies Franking Data for Message
    println!("===> Receiver Verifying Franking Data for Message");
    let enc_tag = receiver
        .verify(&moderator.pk, &fd, m.as_bytes(), t_msg, &ctx)
        .expect("Franking data verification failed.");

    // Moderator Verifies Franking Data for Message for Moderation
    println!("===> Moderator Verifying Franking Data for Message");
    let mod_verify_success = moderator.moderate(&k_f, m.as_bytes(), t_msg, &ctx, &enc_tag);
    status!(
        mod_verify_success,
        "Moderator successfully verified franking data for message and tag.",
        "Moderator rejected franking data for message and tag."
    );

    if print_costs {
        // Communication Cost of Moderation (Inputs to Moderate)
        // (1) Ciphertext (enc_tag): 2 CompressedRistretto
        // (2) Message Timestamp (t_msg): 1 u64
        let mod_cost = mem::size_of::<CompressedRistretto>() * 2 + mem::size_of::<u64>();
        println!("Moderation Communication Cost: {} (bytes)", mod_cost);
    }

    println!();
    println!(
        "======================== Completed Testing ElGamal Scheme with Message of Size {} ====================",
        msg_size
    );
    println!();
    println!();
}
