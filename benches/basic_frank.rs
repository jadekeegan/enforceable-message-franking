use criterion::*;
use federated_franking_impl::schemes::lib_basic as basic;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_basic_frank(c: &mut Criterion) {
    // Setup Moderator
    let moderators = basic::test_basic_init_moderators(1);
    let moderator = &moderators[0];

    // Setup Clients
    let clients = basic::test_basic_init_clients(2);
    let sender = &clients[0];
    let receiver = &clients[1];

    let t_expiry = compute_timestamp(WEEK_OFFSET);

    // Setup Session
    let (k_f, k_pub) = basic::test_basic_set_up_session(moderator, sender, receiver, t_expiry);

    // Generate test messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(basic::test_basic_init_messages(1, *msg_size));
    }
    let t_msg = compute_timestamp(0);

    let mut group = c.benchmark_group("basic.send()");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(
            format!("basic.frank() message of size {}", msg_size),
            msg_size,
            |b, &_msg_size| {
                b.iter(|| {
                    basic::test_frank_message(
                        sender,
                        receiver,
                        &k_f,
                        &k_pub,
                        ms[j][0].as_bytes(), // Convert String to &[u8]
                        t_msg,
                    );
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_basic_frank);
criterion_main!(benches);
