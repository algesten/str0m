#![no_main]

use libfuzzer_sys::fuzz_target;
use str0m::_internal_test_exports::fuzz::*;

fuzz_target!(|data: &[u8]| {
    sdp_offer(data);
});
