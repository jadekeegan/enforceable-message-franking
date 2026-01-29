use criterion::*;
use federated_franking_impl::toolbox::lib_common::user_keygen;

pub fn bench_user_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("client.keygen()");
    group.bench_function("user_keygen()", |b| b.iter(user_keygen));
    group.finish();
}

criterion_group!(benches, bench_user_keygen);
criterion_main!(benches);
