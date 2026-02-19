use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_compute_public_key(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (_client, k_f, r, _k_pub) = test_lite_init_client_with_keys(t_expiry);

    // Benchmark
    let mut group = c.benchmark_group("common");
    group.bench_function("compute_public_key()", |b| {
        b.iter(|| black_box(compute_public_key(&k_f, &r)))
    });
    group.finish();
}

criterion_group!(benches, bench_compute_public_key);
criterion_main!(benches);
