use criterion::*;
use curve25519_dalek::RistrettoPoint;
use federated_franking_impl::toolbox::lib_emf_enc as emf;
use rand::rngs::OsRng;

pub fn bench_emf_encrypt(c: &mut Criterion) {
    // Setup: Generate keypair and random point
    let (_sk, pk) = emf::keygen();
    let point = RistrettoPoint::random(&mut OsRng).compress();

    // Benchmark
    let mut group = c.benchmark_group("emf_enc");
    group.bench_function("encrypt()", |b| {
        b.iter(|| black_box(emf::encrypt(&pk, &point)))
    });
    group.finish();
}

criterion_group!(benches, bench_emf_encrypt);
criterion_main!(benches);
