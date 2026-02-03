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
}

fn main() {
    let args = Args::parse();

    if args.basic {
        test_basic(args.msg_size);
    }

    if args.elgamal {
        test_elgamal(args.msg_size);
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
pub fn test_basic(msg_size: usize) {
    println!(
        "======================== Started Testing Basic Scheme with Message of Size {} ====================",
        msg_size
    );
    println!();

    // Initialize Session Data (sets up moderator, sender, receiver, and sender keys)
    println!("===> Initializing Moderator, Sender, Receiver, and Sender Keys");
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (moderator, sender, receiver, k_f, ctx, sig) = test_basic_init_full_session_data(t_expiry);

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
    let accept_session_success = receiver.accept_session(&moderator.pk, &ctx, &sig);
    status!(
        accept_session_success,
        "Receiver successfully accepted sender session.",
        "Receiver rejected sender session."
    );

    // Initialize Message
    let m = test_init_message(msg_size);
    let t_msg = compute_timestamp(0);

    // Sender Frank Message
    println!("===> Sender Franking Message");
    let fd = sender.frank(&receiver.pk, &k_f, m.as_bytes(), t_msg, &ctx);

    // Receiver Verifies Franking Data for Message
    println!("===> Receiver Verifying Franking Data for Message");
    let tag = receiver
        .verify(&fd, m.as_bytes(), t_msg, &ctx)
        .expect("Franking data verification failed.");

    // Moderator Verifies Franking Data for Message for Moderation
    println!("===> Moderator Verifying Franking Data for Message");
    let mod_verify_success = moderator.moderate(&k_f, m.as_bytes(), t_msg, &ctx, &tag);
    status!(
        mod_verify_success,
        "Moderator successfully verified franking data for message and tag.",
        "Moderator rejected franking data for message and tag."
    );

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
pub fn test_elgamal(msg_size: usize) {
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

    // Initialize Message
    let m = test_init_message(msg_size);
    let t_msg = compute_timestamp(0);

    // Sender Frank Message
    println!("===> Sender Franking Message");
    let fd = sender.frank(&moderator.pk, &receiver.pk, &k_f, m.as_bytes(), t_msg, &ctx);

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
    println!();
    println!(
        "======================== Completed Testing ElGamal Scheme with Message of Size {} ====================",
        msg_size
    );
    println!();
    println!();
}
