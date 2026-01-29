use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_basic_frank(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (_moderator, sender, receiver, k_f, k_pub, _sig) = test_init_full_session_data(t_expiry);

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
                    sender.frank(
                        &receiver.pk,
                        &k_f,
                        &k_pub,
                        ms[j].as_bytes(),
                        (sender.id, t_msg),
                    );
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_basic_frank);
criterion_main!(benches);
