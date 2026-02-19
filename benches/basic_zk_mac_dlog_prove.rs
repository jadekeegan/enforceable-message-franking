use criterion::*;

use federated_franking_impl::schemes::bench_helpers::*;
use federated_franking_impl::toolbox::lib_basic_zkp as zkp;
use federated_franking_impl::toolbox::lib_common::*;
use federated_franking_impl::toolbox::lib_mac_ggm as mac_ggm;

pub fn bench_basic_zk_mac_dlog_prove(c: &mut Criterion) {
    // Set Up Session Data
    let t_expiry = compute_timestamp(WEEK_OFFSET);
    let (_moderator, sender, receiver, k_f, r, ctx, _sig) =
        test_basic_init_full_session_data(t_expiry);

    // Generate test messages of various sizes with franking data
    let t_msg = compute_timestamp(0);
    let (ms, fds) = test_basic_init_messages_with_franking_data(
        &sender,
        &receiver.pk,
        &k_f,
        &r,
        &ctx.k_pub,
        t_msg,
    );

    // Benchmark
    let mut group = c.benchmark_group("basic/zk");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(
            format!("zk_mac_dlog_prove() message of size {}", msg_size),
            msg_size,
            |b, &_msg_size| {
                let h_m = mac_ggm::hash_context(ms[j].as_bytes(), &ctx.id, t_msg);

                b.iter(|| {
                    black_box(zkp::zk_mac_dlog_prove(
                        &fds[j].r_point,
                        &k_f,
                        &r,
                        &fds[j].tag,
                        ms[j].as_bytes(), // Convert String to &[u8]
                        &h_m,
                        t_msg,
                        &ctx,
                    ));
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_basic_zk_mac_dlog_prove);
criterion_main!(benches);
