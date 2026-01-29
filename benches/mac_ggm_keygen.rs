use criterion::*;

use federated_franking_impl::toolbox::lib_mac_ggm as mac_ggm;

pub fn bench_ggm_mac_keygen(c: &mut Criterion) {
    // Benchmark
    let mut group = c.benchmark_group("mac_ggm.mac_keygen()");
    group.bench_function("mac_ggm.mac_keygen()", |b| b.iter(mac_ggm::keygen));
    group.finish();
}

criterion_group!(benches, bench_ggm_mac_keygen);
criterion_main!(benches);
