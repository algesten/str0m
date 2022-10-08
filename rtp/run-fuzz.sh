#!/bin/sh

rm -rf fuzz && cargo +nightly fuzzcheck tests::fuzz_twcc --stop-after-first-failure
