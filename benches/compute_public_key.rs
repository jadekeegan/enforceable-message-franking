use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_compute_public_key(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (_client, k_f, _k_pub) = test_basic_init_client_with_keys(t_expiry);

    // Benchmark
    c.bench_function("compute_public_key()", |b| {
        b.iter(|| compute_public_key(&k_f))
    });
}

criterion_group!(benches, bench_compute_public_key);
criterion_main!(benches);
