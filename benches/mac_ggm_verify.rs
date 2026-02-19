use criterion::*;

use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_common::*;
use federated_franking_impl::toolbox::lib_mac_ggm as mac_ggm;

pub fn bench_ggm_mac_verify(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (client, k_f, _r, _k_pub) = test_lite_init_client_with_keys(t_expiry);

    // Generate test messages of various sizes
    let (ms, tags) = test_lite_init_messages_with_tags(&k_f, &client, compute_timestamp(0));
    let t_msg = compute_timestamp(0);

    // Benchmark
    let mut group = c.benchmark_group("mac_ggm");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(
            format!("verify() message of size {}", msg_size),
            msg_size,
            |b, &_msg_size| {
                b.iter(|| {
                    black_box(mac_ggm::verify(
                        &k_f,
                        ms[j].as_bytes(),
                        &client.id,
                        t_msg,
                        &tags[j],
                    ));
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_ggm_mac_verify);
criterion_main!(benches);
