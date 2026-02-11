use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

// Note: Although we use the basic moderator's register_user, the benchmark is valid for both schemes since we
// use the same helper function in each. We use the scheme specific method rather than the common helper
// since we need the moderator secret key for register_user.
pub fn bench_basic_register_user(c: &mut Criterion) {
    // Set Up Data
    let (moderator, client) = test_basic_init_moderator_client();
    let t_expiry = compute_timestamp(WEEK_OFFSET);

    // Benchmark
    let mut group = c.benchmark_group("common");
    group.bench_function("register_user()", |b| {
        b.iter(|| black_box(moderator.register_user(&client.id, t_expiry)));
    });
    group.finish();
}

criterion_group!(benches, bench_basic_register_user);
criterion_main!(benches);
