use criterion::{black_box, criterion_group, criterion_main, Criterion};
use str0m::bench::srtp::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("aead_aes_128_gcm_protect_rtp", |b| {
        let mut context = Context::aead_aes_128_gcm_protect_rtp();

        b.iter(|| black_box(context.benchmark_protect_rtp()));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
