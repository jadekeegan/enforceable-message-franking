use criterion::*;
use federated_franking_impl::toolbox::lib_common::moderator_keygen;

pub fn bench_moderator_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("moderator.keygen()");
    group.bench_function("moderator_keygen()", |b| b.iter(moderator_keygen));
    group.finish();
}

criterion_group!(benches, bench_moderator_keygen);
criterion_main!(benches);
