use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_basic_frank(c: &mut Criterion) {
    let (moderator, sender, receiver) = test_session_set_up();
    let t_expiry = compute_timestamp(WEEK_OFFSET);

    // Register User to get Franking and Public Keys
    let (k_f, k_pub) = test_register_user(&moderator, &sender, t_expiry);

    // Generate test messages of various sizes
    let ms = test_basic_init_messages();
    let t_msg = compute_timestamp(0);

    // Benchmark
    let mut group = c.benchmark_group("basic.frank()");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(
            format!("basic.frank() message of size {}", msg_size),
            msg_size,
            |b, &_msg_size| {
                b.iter(|| {
                    test_frank_message(
                        &sender,
                        &receiver,
                        &k_f,
                        &k_pub,
                        ms[j].as_bytes(), // Convert String to &[u8]
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
