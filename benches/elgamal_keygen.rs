use criterion::*;
use federated_franking_impl::toolbox::lib_elgamal as elgamal;

pub fn bench_elgamal_keygen(c: &mut Criterion) {
    // Benchmark
    let mut group = c.benchmark_group("elgamal");
    group.bench_function("keygen()", |b| b.iter(|| black_box(elgamal::keygen())));
    group.finish();
}

criterion_group!(benches, bench_elgamal_keygen);
criterion_main!(benches);
