# str0m-apple-crypto

Apple CryptoKit/CommonCrypto/Security framework backend for [str0m](https://github.com/algesten/str0m).

## Building

Requires macOS 10.15+ or iOS 13+, and an Apple Swift toolchain (Swift 5.7+
with the target SDK installed). Cargo uses `swift-rs` at build time to compile
the local [Swift bridge](swift/) and link it with the Swift runtime. There are
no external Swift package dependencies.

Hashes, HMAC and AES-GCM call CryptoKit directly through the bridge.
CommonCrypto supplies AES-ECB for SRTP key derivation and DTLS record number
protection; key and certificate operations use Security.framework.

The bridge borrows input buffers directly, including fragmented HMAC messages
and SRTP associated data. AES-GCM ciphers retain their CryptoKit key between
packets. DTLS writes results back into its existing buffers after successful
encryption or authentication. CryptoKit's public AES-GCM API still produces
owned output, which the bridge copies into the caller's buffer.

## Usage

The primary way to use this backend is via the `apple-crypto` feature flag in `str0m`:

```toml
[dependencies]
str0m = { version = "0.14", features = ["apple-crypto"] }
```

## Advanced: Direct usage

For advanced use cases, you can use this crate directly without enabling the feature flag:

```rust
use str0m::Rtc;
use std::sync::Arc;

// Set as process-wide default
str0m_apple_crypto::default_provider().install_process_default();

// Or configure per-instance
let rtc = Rtc::builder()
    .set_crypto_provider(Arc::new(str0m_apple_crypto::default_provider()))
    .build();
```
