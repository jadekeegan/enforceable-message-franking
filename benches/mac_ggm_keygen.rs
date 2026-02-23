use criterion::*;

use enforceable_message_franking::toolbox::lib_mac_ggm as mac_ggm;

pub fn bench_ggm_mac_keygen(c: &mut Criterion) {
    // Benchmark
    let mut group = c.benchmark_group("mac_ggm");
    group.bench_function("keygen()", |b| b.iter(|| black_box(mac_ggm::keygen())));
    group.finish();
}

criterion_group!(benches, bench_ggm_mac_keygen);
criterion_main!(benches);
