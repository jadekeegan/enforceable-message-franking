use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_basic_session_init(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (moderator, sender, _receiver, k_f, k_pub, sig) = test_init_full_session_data(t_expiry);

    // Benchmark
    let mut group = c.benchmark_group("basic.session_init()");
    group.bench_function("basic.session_init()", |b| {
        b.iter(|| test_basic_session_init(&moderator.pk, &sender, &k_f, &k_pub, t_expiry, &sig))
    });
    group.finish();
}

criterion_group!(benches, bench_basic_session_init);
criterion_main!(benches);
