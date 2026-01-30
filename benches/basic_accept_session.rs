use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_basic_accept_session(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (moderator, sender, receiver, _k_f, k_pub, sig) =
        test_basic_init_full_session_data(t_expiry);

    // Benchmark
    let mut group = c.benchmark_group("basic");
    group.bench_function("accept_session()", |b| {
        b.iter(|| receiver.accept_session(&moderator.pk, &sender.id, &k_pub, t_expiry, &sig))
    });
    group.finish();
}

criterion_group!(benches, bench_basic_accept_session);
criterion_main!(benches);
