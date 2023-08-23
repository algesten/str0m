# Method used to benchmark

```bash
cargo bench --features bench cache_sent_packet
```

The problem with the test is that we need to do Vec allocations to get
realistic values inside the test. This gives a big overhead to the test
harness itself.

1. Comment out all operations inside `cache_sent_packet` making it a noop.
2. Run bench. This gives a baseline of overhead for the test itself. Result: 2.3ms
3. Enable operations again. In bench.rs disable _evict in batches_.
4. Run bench. Result: 7.1ms
5. Enable _evict in batches_.
6. Run bench. Result: 6.1ms
7. Optimize using fixed size array for seq_no_by_quantized_size
8. Run bench. Result: 5.3ms

```
                 Total time     Less overhead
Unoptimized      7.1            4.8
evict_in_batches 6.1            3.8
fixed size arr   5.3            3
```
