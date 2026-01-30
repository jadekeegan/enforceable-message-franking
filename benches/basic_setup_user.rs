use criterion::*;
use federated_franking_impl::schemes::lib_basic as basic;

pub fn bench_basic_setup_user(c: &mut Criterion) {
    let mut group = c.benchmark_group("basic");
    group.bench_function("setup_user()", |b| b.iter(|| black_box(basic::Client::new())));
    group.finish();
}

criterion_group!(benches, bench_basic_setup_user);
criterion_main!(benches);
