# str0m-wincrypto

Windows CNG crypto backend with DTLS 1.2 and 1.3 provided by dimpl for [str0m](https://github.com/algesten/str0m).

## Usage

The primary way to use this backend is via the `wincrypto` feature flag in `str0m`:

```toml
[dependencies]
str0m = { version = "0.23", default-features = false, features = ["wincrypto"] }
```

The `wincrypto-dimpl` feature in str0m remains an alias for `wincrypto`.
The `dimpl` feature in this crate is retained for compatibility; dimpl is always enabled.

## Advanced: Direct usage

For advanced use cases, you can use this crate directly without enabling the feature flag:

```rust
use str0m::Rtc;
use std::sync::Arc;

// Set as process-wide default
str0m_wincrypto::default_provider().install_process_default();

// Or configure per-instance
let rtc = Rtc::builder()
    .set_crypto_provider(Arc::new(str0m_wincrypto::default_provider()))
    .build();
```
