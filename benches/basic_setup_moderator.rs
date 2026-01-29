use criterion::*;
use federated_franking_impl::schemes::lib_basic as basic;

pub fn bench_basic_setup_moderator(c: &mut Criterion) {
    let mut group = c.benchmark_group("basic.setup_moderator()");
    group.bench_function("basic.setup_moderator()", |b| b.iter(basic::Moderator::new));
    group.finish();
}

criterion_group!(benches, bench_basic_setup_moderator);
criterion_main!(benches);
