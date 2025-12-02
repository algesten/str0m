# str0m-wincrypto

Windows CNG/SChannel crypto provider for [str0m](https://github.com/algesten/str0m).

This crate provides a `CryptoProvider` implementation using Windows native cryptography APIs:
- **SChannel** for DTLS 1.2
- **CNG (Cryptography Next Generation)** for SRTP encryption
- **CNG** for SHA1-HMAC (STUN) and SHA-256 (fingerprints)

## Usage

Add both `str0m` and `str0m-wincrypto` to your `Cargo.toml`:

```toml
[dependencies]
str0m = { version = "0.12", default-features = false }
str0m-wincrypto = "0.2"
```

Then create an `RtcConfig` with the Windows crypto provider:

```rust
use std::sync::Arc;
use str0m::RtcConfig;
use str0m_wincrypto::default_provider;

let crypto_provider = Arc::new(default_provider());
let config = RtcConfig::new().set_crypto_provider(crypto_provider);
let mut rtc = config.build();
```

## Supported SRTP Profiles

- `SRTP_AES128_CM_SHA1_80`
- `SRTP_AEAD_AES_128_GCM`  
- `SRTP_AEAD_AES_256_GCM`

## Platform Support

This crate only works on Windows platforms and requires Windows 8 or later.
