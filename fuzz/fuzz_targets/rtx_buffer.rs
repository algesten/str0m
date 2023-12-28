#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};
use str0m::_interna_test_exports::fuzz::*;

fuzz_target!(|data: &[u8]| rtx_buffer(data));
