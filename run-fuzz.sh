#!/bin/sh

cargo +nightly fuzz run rtx_buffer -- --stop-after-first-failure
