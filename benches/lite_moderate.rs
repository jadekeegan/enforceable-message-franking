use criterion::*;
use enforceable_message_franking::schemes::bench_helpers::*;
use enforceable_message_franking::toolbox::lib_common::*;

pub fn bench_lite_moderate(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (moderator, sender, receiver, k_f, r, ctx, _sig) =
        test_lite_init_full_session_data(t_expiry);

    // Generate test messages of various sizes with corresponding franking data
    let t_msg = compute_timestamp(0);
    let (ms, fds) = test_lite_init_messages_with_franking_data(
        &sender,
        &receiver.pk,
        &k_f,
        &r,
        &ctx.k_pub,
        t_msg,
    );

    // Benchmark
    let mut group = c.benchmark_group("lite/moderate");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(
            format!("moderate() message of size {}", msg_size),
            msg_size,
            |b, &_msg_size| {
                b.iter(|| {
                    black_box(moderator.moderate(&k_f, ms[j].as_bytes(), t_msg, &ctx, &fds[j].tag));
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_lite_moderate);
criterion_main!(benches);
