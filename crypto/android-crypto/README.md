# str0m-android-crypto

Android JNI cryptographic backend for [str0m](https://github.com/algesten/str0m).

This crate provides cryptographic operations for WebRTC by calling into Android's
`javax.crypto` and `java.security` APIs via JNI.

## Prerequisites

This crate requires:
- Android NDK for cross-compilation
- A JVM available at runtime (provided by Android)
- The JNI environment to be initialized (see below)

## Usage

The primary way to use this backend is via the `android-crypto` feature flag in `str0m`:

```toml
[dependencies]
str0m = { version = "0.14", features = ["android-crypto"] }
```

## Initialization

Before using the crypto provider, you must initialize it with the JNI environment.
This is typically done in your JNI_OnLoad function or at application startup:

```rust
use jni::JavaVM;
use str0m_android_crypto;

// In your JNI_OnLoad or initialization code
#[no_mangle]
pub extern "C" fn JNI_OnLoad(vm: jni::JavaVM, _reserved: *mut std::ffi::c_void) -> jni::sys::jint {
    // Initialize the crypto provider with the JVM
    str0m_android_crypto::init_jvm(vm);
    
    jni::sys::JNI_VERSION_1_6
}
```

## Advanced: Direct usage

For advanced use cases, you can use this crate directly:

```rust
use str0m::Rtc;
use std::sync::Arc;

// After JVM initialization...

// Set as process-wide default
str0m_android_crypto::default_provider().install_process_default();

// Or configure per-instance
let rtc = Rtc::builder()
    .set_crypto_provider(Arc::new(str0m_android_crypto::default_provider()))
    .build();
```

## Supported Algorithms

### SRTP Profiles
- `SRTP_AES128_CM_SHA1_80`
- `SRTP_AEAD_AES_128_GCM`
- `SRTP_AEAD_AES_256_GCM`

### DTLS
- DTLS 1.2 with ECDHE-ECDSA cipher suites
- DTLS 1.3 support

### Hash Functions
- SHA-256 for certificate fingerprints
- SHA1-HMAC for STUN message integrity

## Android API Level

This crate targets Android API level 21+ (Android 5.0 Lollipop) which provides
all the necessary crypto APIs:
- `javax.crypto.Cipher` with AES/GCM/NoPadding
- `javax.crypto.Mac` with HmacSHA1 and HmacSHA256
- `java.security.MessageDigest` with SHA-256
- `java.security.KeyPairGenerator` with EC
- `java.security.Signature` with SHA256withECDSA
- `javax.crypto.KeyAgreement` with ECDH
