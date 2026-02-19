use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_basic_accept_session(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (moderator, _sender, _receiver, _k_f, _r, ctx, sig) =
        test_lite_init_full_session_data(t_expiry);
    let compressed_ctx = ctx.compress();

    // Benchmark
    let mut group = c.benchmark_group("common");
    group.bench_function("accept_session()", |b| {
        b.iter(|| black_box(accept_session(&moderator.pk, &compressed_ctx, &sig)))
    });
    group.finish();
}

criterion_group!(benches, bench_basic_accept_session);
criterion_main!(benches);
