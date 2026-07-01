#![no_main]

use libfuzzer_sys::fuzz_target;
use str0m::rtp::RedDecoder;

fuzz_target!(|data: &[u8]| {
    // RFC 2198 RED payloads come from untrusted peers; decoding must never panic.
    let _ = RedDecoder::decode(data);
});
