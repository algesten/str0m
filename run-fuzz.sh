#!/bin/sh

# This is for macOS.
# For linux use: NUM_CPUS=$(awk '/^processor/ {++n} END {print n+1}' /proc/cpuinfo)
NUM_CPUS=$(sysctl -n hw.ncpu)

if [ "$1" == "" ]; then
    cargo +nightly fuzz list --fuzz-dir crates/fuzz
else
    cargo +nightly fuzz run $1 --fuzz-dir crates/fuzz --jobs $NUM_CPUS -- --stop-after-first-failure -max_len=200000
fi
