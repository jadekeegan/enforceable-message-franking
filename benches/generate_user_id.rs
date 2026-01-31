use criterion::*;
use federated_franking_impl::toolbox::lib_common::generate_user_id;

pub fn bench_generate_user_id(c: &mut Criterion) {
    let mut group = c.benchmark_group("common");
    group.bench_function("generate_user_id()", |b| b.iter(|| black_box(generate_user_id())));
    group.finish();
}

criterion_group!(benches, bench_generate_user_id);
criterion_main!(benches);
