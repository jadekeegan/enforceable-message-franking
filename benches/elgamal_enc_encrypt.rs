use criterion::*;
use curve25519_dalek::RistrettoPoint;
use federated_franking_impl::toolbox::lib_elgamal_enc as elgamal;
use rand::rngs::OsRng;

pub fn bench_elgamal_encrypt(c: &mut Criterion) {
    // Setup: Generate keypair and random point
    let (_sk, pk) = elgamal::keygen();
    let point = RistrettoPoint::random(&mut OsRng);

    // Benchmark
    let mut group = c.benchmark_group("elgamal_enc");
    group.bench_function("encrypt()", |b| {
        b.iter(|| black_box(elgamal::encrypt(&pk, &point)))
    });
    group.finish();
}

criterion_group!(benches, bench_elgamal_encrypt);
criterion_main!(benches);
