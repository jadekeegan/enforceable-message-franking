use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_lite_frank(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (_moderator, sender, receiver, k_f, r, ctx, _sig) =
        test_lite_init_full_session_data(t_expiry);

    // Generate test messages of various sizes
    let ms = test_init_messages();
    let t_msg = compute_timestamp(0);

    // Benchmark
    let mut group = c.benchmark_group("lite/frank");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(
            format!("frank() message of size {}", msg_size),
            msg_size,
            |b, &_msg_size| {
                b.iter(|| {
                    black_box(sender.frank(&receiver.pk, &k_f, &r, ms[j].as_bytes(), t_msg, &ctx));
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_lite_frank);
criterion_main!(benches);
