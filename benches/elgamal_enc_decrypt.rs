use criterion::*;
use curve25519_dalek::RistrettoPoint;
use federated_franking_impl::toolbox::lib_elgamal_enc as elgamal;
use rand::rngs::OsRng;

pub fn bench_elgamal_decrypt(c: &mut Criterion) {
    // Generate keypair and random ciphertext
    let (sk, pk) = elgamal::keygen();
    let point = RistrettoPoint::random(&mut OsRng);
    let (ct, _r) = elgamal::encrypt(&pk, &point);

    // Benchmark
    let mut group = c.benchmark_group("elgamal_enc");
    group.bench_function("decrypt()", |b| {
        b.iter(|| black_box(elgamal::decrypt(&sk, &ct)))
    });
    group.finish();
}

criterion_group!(benches, bench_elgamal_decrypt);
criterion_main!(benches);
