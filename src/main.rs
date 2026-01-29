use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

use clap::Parser;

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

    #[arg(long, default_value_t = 100)]
    msg_size: usize,
}

fn main() {
    let args = Args::parse();

    if args.basic {
        test_basic(args.msg_size);
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
    let (moderator, sender, receiver, k_f, k_pub, sig) =
        test_basic_init_full_session_data(t_expiry);

    // Sender Initializes Session
    println!("===> Sender Initializing Session");
    let session_init_success = sender.session_init(&moderator.pk, &k_f, &k_pub, t_expiry, &sig);
    status!(
        session_init_success,
        "Sender session initialization successful.",
        "Sender session initialization failed."
    );

    // Receiver Verifies and Accepts Sender Session
    println!("===> Receiver Accepting Sender Session");
    let accept_session_success =
        receiver.accept_session(&moderator.pk, &sender.id, &k_pub, t_expiry, &sig);
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
    let fd = sender.frank(&receiver.pk, &k_f, &k_pub, m.as_bytes(), (sender.id, t_msg));

    // Receiver Verifies Franking Data for Message
    println!("===> Receiver Verifying Franking Data for Message");
    let tag = receiver
        .verify(
            &receiver.pk,
            &fd,
            m.as_bytes(),
            (sender.id, t_msg),
            t_expiry,
        )
        .expect("Franking data verification failed.");

    // Moderator Verifies Franking Data for Message for Moderation
    println!("===> Moderator Verifying Franking Data for Message");
    let mod_verify_success =
        moderator.moderate(&k_f, t_expiry, m.as_bytes(), (sender.id, t_msg), &tag);
    status!(
        mod_verify_success,
        "Moderator successfully verified franking data for message and tag report.",
        "Moderator rejected franking data for message and tag report."
    );

    println!();
    println!(
        "======================== Completed Testing Basic Scheme with Message of Size {} ====================",
        msg_size
    );
    println!();
    println!();
}
