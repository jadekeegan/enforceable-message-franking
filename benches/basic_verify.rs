use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_basic_verify(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (_moderator, sender, receiver, k_f, r, ctx, _sig) =
        test_basic_init_full_session_data(t_expiry);

    // Generate test messages of various sizes with corresponding franking data
    let t_msg = compute_timestamp(0);
    let (ms, fds) = test_basic_init_messages_with_franking_data(
        &sender,
        &receiver.pk,
        &k_f,
        &r,
        &ctx.k_pub,
        t_msg,
    );

    // Benchmark
    let mut group = c.benchmark_group("basic/verify");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(
            format!("verify() message of size {}", msg_size),
            msg_size,
            |b, &_msg_size| {
                b.iter(|| black_box(receiver.verify(&fds[j], ms[j].as_bytes(), t_msg, &ctx)))
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_basic_verify);
criterion_main!(benches);
