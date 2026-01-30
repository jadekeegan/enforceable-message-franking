use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_basic_register_user(c: &mut Criterion) {
    // Set Up Data
    let (moderator, client) = test_basic_init_moderator_client();
    let t_expiry = compute_timestamp(WEEK_OFFSET);

    // Benchmark
    let mut group = c.benchmark_group("basic");
    group.bench_function("register_user()", |b| {
        b.iter(|| moderator.register_user(&client.id, t_expiry));
    });
    group.finish();
}

criterion_group!(benches, bench_basic_register_user);
criterion_main!(benches);
