use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_elgamal_verify(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (moderator, sender, receiver, k_f, k_pub, _sig) =
        test_elgamal_init_full_session_data(t_expiry);

    // Generate test messages of various sizes with corresponding franking data
    let t_msg = compute_timestamp(0);
    let (ms, fds) = test_elgamal_init_messages_with_franking_data(
        &sender,
        &moderator.pk,
        &receiver.pk,
        &k_f,
        &k_pub,
        t_msg,
    );

    // Benchmark
    let mut group = c.benchmark_group("elgamal");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(
            format!("verify() message of size {}", msg_size),
            msg_size,
            |b, &_msg_size| {
                b.iter(|| {
                    black_box(receiver.verify(
                        &moderator.pk,
                        &receiver.pk,
                        &fds[j],
                        ms[j].as_bytes(),
                        (sender.id, t_msg),
                        t_expiry,
                    ))
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_elgamal_verify);
criterion_main!(benches);
