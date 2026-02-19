use criterion::*;
use federated_franking_impl::schemes::lib_lite as lite;

pub fn bench_moderator_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("lite");
    group.bench_function("moderator_keygen()", |b| {
        b.iter(|| black_box(lite::moderator_keygen()))
    });
    group.finish();
}

criterion_group!(benches, bench_moderator_keygen);
criterion_main!(benches);
