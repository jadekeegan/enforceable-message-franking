use criterion::*;
use enforceable_message_franking::schemes::bench_helpers::*;
use enforceable_message_franking::toolbox::lib_common::*;

pub fn bench_session_init(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (moderator, _sender, _receiver, k_f, r, ctx, sig) =
        test_lite_init_full_session_data(t_expiry);
    let compressed_ctx = ctx.compress();

    // Benchmark
    let mut group = c.benchmark_group("common");
    group.bench_function("session_init()", |b| {
        b.iter(|| black_box(session_init(&moderator.pk, &k_f, &r, &compressed_ctx, &sig)))
    });
    group.finish();
}

criterion_group!(benches, bench_session_init);
criterion_main!(benches);
