use criterion::*;
use federated_franking_impl::toolbox::lib_emf_enc as emf_enc;

pub fn bench_emf_keygen(c: &mut Criterion) {
    // Benchmark
    let mut group = c.benchmark_group("emf_enc");
    group.bench_function("keygen()", |b| b.iter(|| black_box(emf_enc::keygen())));
    group.finish();
}

criterion_group!(benches, bench_emf_keygen);
criterion_main!(benches);
