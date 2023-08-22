use criterion::{black_box, criterion_group, criterion_main, Criterion};
use str0m::bench::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("cache_sent_packet", |b| {
        b.iter(|| black_box(benchmark_cache_sent_packet()));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
