use criterion::*;

use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;
use federated_franking_impl::toolbox::lib_mac_ggm as mac_ggm;

pub fn bench_ggm_hash_context(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (client, _k_f, _k_pub) = test_basic_init_client_with_keys(t_expiry);

    // Initialize messages of varying sizes
    let ms = test_init_messages();
    let t_msg = compute_timestamp(0);
    let ctx = (client.id, t_msg);

    // Benchmark
    let mut group = c.benchmark_group("mac_ggm");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(
            format!("hash_context() message of size {}", msg_size),
            msg_size,
            |b, &_msg_size| {
                b.iter(|| {
                    black_box(mac_ggm::hash_context(ms[j].as_bytes(), ctx));
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_ggm_hash_context);
criterion_main!(benches);
