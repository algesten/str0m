# str0m-openssl

OpenSSL backend for [str0m](https://github.com/algesten/str0m).

## Usage

The primary way to use this backend is via the `openssl` feature flag in `str0m`:

```toml
[dependencies]
str0m = { version = "0.14", default-features = false, features = ["openssl"] }
```

## Advanced: Direct usage

For advanced use cases, you can use this crate directly without enabling the feature flag:

```rust
use str0m::Rtc;
use std::sync::Arc;

// Set as process-wide default
str0m_openssl::default_provider().install_process_default();

// Or configure per-instance
let rtc = Rtc::builder()
    .set_crypto_provider(Arc::new(str0m_openssl::default_provider()))
    .build();
```
