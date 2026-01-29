use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;

pub fn bench_serialize_registration(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = 1_000_000u64;
    let (sender, _k_f, k_pub) = test_init_client_with_keys(t_expiry);

    // Benchmark
    let mut group = c.benchmark_group("serialize_registration()");
    group.bench_function("serialize_registration()", |b| {
        b.iter(|| test_serialize_registration(&sender.id, &k_pub, t_expiry))
    });
    group.finish();
}

criterion_group!(benches, bench_serialize_registration);
criterion_main!(benches);
