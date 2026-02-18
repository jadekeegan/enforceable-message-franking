use criterion::*;
use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_serialize_registration(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (sender, _k_f, _r, k_pub) = test_basic_init_client_with_keys(t_expiry);

    let ctx = SessionContext {
        id: sender.id,
        k_pub,
        t_expiry,
    };

    // Benchmark
    let mut group = c.benchmark_group("common");
    group.bench_function("serialize_registration()", |b| {
        b.iter(|| black_box(serialize_registration(&ctx)))
    });
    group.finish();
}

criterion_group!(benches, bench_serialize_registration);
criterion_main!(benches);
