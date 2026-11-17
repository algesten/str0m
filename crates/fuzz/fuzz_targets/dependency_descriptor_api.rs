#![no_main]

use libfuzzer_sys::fuzz_target;
use str0m::_internal_test_exports::fuzz::*;

fuzz_target!(|data: &[u8]| {
    // Encoders and SFUs pass their own values to the Dependency Descriptor API.
    dependency_descriptor_api(data);
});
