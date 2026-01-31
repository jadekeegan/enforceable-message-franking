use criterion::*;
use federated_franking_impl::toolbox::lib_common::*;

pub fn bench_compute_timestamp(c: &mut Criterion) {
    let mut group = c.benchmark_group("common");
    for &offset in [0u64, HOUR_OFFSET, DAY_OFFSET, WEEK_OFFSET].iter() {
        group.bench_with_input(
            format!("compute_timestamp() with offset {}", offset),
            &offset,
            |b, &offset| {
                b.iter(|| {
                    black_box(compute_timestamp(offset));
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_compute_timestamp);
criterion_main!(benches);
