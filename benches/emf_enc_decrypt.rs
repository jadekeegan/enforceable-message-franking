use criterion::*;
use curve25519_dalek::RistrettoPoint;
use federated_franking_impl::toolbox::lib_emf_enc as emf;
use rand::rngs::OsRng;

pub fn bench_emf_decrypt(c: &mut Criterion) {
    // Generate keypair and random ciphertext
    let (sk, pk) = emf::keygen();
    let point = RistrettoPoint::random(&mut OsRng).compress();
    let (ct, _r) = emf::encrypt(&pk, &point);

    // Benchmark
    let mut group = c.benchmark_group("emf_enc");
    group.bench_function("decrypt()", |b| {
        b.iter(|| black_box(emf::decrypt(&sk, &ct)))
    });
    group.finish();
}

criterion_group!(benches, bench_emf_decrypt);
criterion_main!(benches);
