#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};
use str0m::fuzz::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let buf_size = u16::from_be_bytes([data[0], data[1]]);
    let max_age = data[2] as u64;
    let mut buf = EvictingBuffer::new(buf_size as usize, Duration::from_secs(max_age));
    let mut now = Instant::now();
    let mut pos = 0;

    for d in &data[4..] {
        now += Duration::from_millis(*d as u64);
        if d % 2 == 0 {
            buf.maybe_evict(now)
        } else {
            pos += *d as u64;
            buf.push(pos, now, d);
        }
    }
});
