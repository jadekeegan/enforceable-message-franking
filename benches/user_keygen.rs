use criterion::*;
use enforceable_message_franking::toolbox::lib_common::user_keygen;

pub fn bench_user_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("common");
    group.bench_function("user_keygen()", |b| b.iter(|| black_box(user_keygen())));
    group.finish();
}

criterion_group!(benches, bench_user_keygen);
criterion_main!(benches);
