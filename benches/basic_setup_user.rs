use criterion::*;
use federated_franking_impl::schemes::lib_basic as basic;

pub fn bench_basic_setup_user(c: &mut Criterion) {
    let mut group = c.benchmark_group("basic.setup_user()");
    group.bench_function("basic.setup_user()", |b| b.iter(basic::Client::new));
    group.finish();
}

criterion_group!(benches, bench_basic_setup_user);
criterion_main!(benches);
