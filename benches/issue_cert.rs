use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

// Note: Although we use the EMF-lite scheme's moderator's issue_cert, the benchmark is valid for both schemes since we
// use the same helper function in each. We use the scheme specific method rather than the common helper
// since we need the moderator secret key for issue_cert.
pub fn bench_issue_cert(c: &mut Criterion) {
    // Set Up Data
    let (moderator, client) = test_lite_init_moderator_client();
    let t_expiry = compute_timestamp(WEEK_OFFSET);

    // Benchmark
    let mut group = c.benchmark_group("common");
    group.bench_function("issue_cert()", |b| {
        b.iter(|| black_box(moderator.issue_cert(&client.id, t_expiry)));
    });
    group.finish();
}

criterion_group!(benches, bench_issue_cert);
criterion_main!(benches);
