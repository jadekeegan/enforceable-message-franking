use criterion::*;
use federated_franking_impl::schemes::lib_basic as basic;

pub fn bench_basic_setup_moderator(c: &mut Criterion) {
    let mut group = c.benchmark_group("basic");
    group.bench_function("setup_moderator()", |b| b.iter(basic::Moderator::new));
    group.finish();
}

criterion_group!(benches, bench_basic_setup_moderator);
criterion_main!(benches);
