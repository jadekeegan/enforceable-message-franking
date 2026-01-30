use criterion::*;
use federated_franking_impl::toolbox::lib_common::moderator_keygen;

pub fn bench_moderator_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("common");
    group.bench_function("moderator_keygen()", |b| b.iter(|| black_box(moderator_keygen())));
    group.finish();
}

criterion_group!(benches, bench_moderator_keygen);
criterion_main!(benches);
