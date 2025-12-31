//! Apple CommonCrypto/Security framework implementation of cryptographic functions.
//! DTLS via dimpl with Apple CommonCrypto as crypto backend.
//!
//! # Performance Notes
//!
//! ## AES-GCM Performance
//!
//! The AES-GCM cipher implementations (AEAD-AES-128-GCM and AEAD-AES-256-GCM) in this
//! provider are **significantly slower** than other implementations (OpenSSL, AWS-LC-RS,
//! RustCrypto). This is due to a limitation in Apple's CommonCrypto API:
//!
//! - CommonCrypto's GCM mode does not support resetting the IV on an existing cryptor
//! - Calling `CCCryptorGCMAddIV()` twice returns error -4308 (`kCCUnspecifiedError`)
//! - `CCCryptorReset()` only works for CBC/CTR modes, not GCM
//! - Therefore, a new `CCCryptorRef` must be created for every encrypt/decrypt operation
//!
//! In benchmarks, this results in ~10x slower performance compared to AWS-LC-RS for
//! GCM operations.
//!
//! ## AES-CTR Performance  
//!
//! The AES-128-CM-SHA1-80 cipher (CTR mode) is optimized by caching the `CCCryptorRef`
//! and using `CCCryptorReset()` to change the IV between operations. This makes CTR
//! mode competitive with other implementations.
//!
//! ## Tradeoffs
//!
//! Despite the GCM performance overhead, using this provider has benefits:
//! - **Smaller binary size** - No bundled crypto library, uses system frameworks
//! - **Native platform crypto** - Uses Apple's audited, hardware-accelerated implementation
//! - **No additional dependencies** - CommonCrypto is always available on Apple platforms
//! - **Compliance** - Some environments require using the platform's native crypto
//!
//! The performance difference may be acceptable depending on your use case. For example,
//! if you're building an iOS app where binary size matters and you're not handling
//! hundreds of concurrent media streams, the GCM overhead may be negligible.
//!
//! **It's up to the user to decide what they prioritize**: raw performance vs. smaller
//! binaries and native platform integration.

#![allow(clippy::redundant_pub_crate)]
#![allow(unsafe_code)]
#![cfg(target_vendor = "apple")]

mod dimpl_provider;
mod dtls;
mod ffi;
mod sha1;
mod sha256;
mod srtp;

use str0m_proto::crypto::CryptoProvider;

use dtls::AppleCryptoDtlsProvider;
use sha1::AppleCryptoSha1HmacProvider;
use sha256::AppleCryptoSha256Provider;
use srtp::AppleCryptoSrtpProvider;

/// Create the default Apple CommonCrypto crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2 for secure key exchange (using dimpl protocol + Apple CommonCrypto)
/// - SRTP for encrypted media
/// - SHA1-HMAC for STUN message integrity
/// - SHA-256 for certificate fingerprints
///
/// # Supported SRTP Profiles
///
/// - `SRTP_AES128_CM_SHA1_80`
/// - `SRTP_AEAD_AES_128_GCM`
/// - `SRTP_AEAD_AES_256_GCM`
pub fn default_provider() -> CryptoProvider {
    static SRTP: AppleCryptoSrtpProvider = AppleCryptoSrtpProvider;
    static SHA1_HMAC: AppleCryptoSha1HmacProvider = AppleCryptoSha1HmacProvider;
    static SHA256: AppleCryptoSha256Provider = AppleCryptoSha256Provider;
    static DTLS: AppleCryptoDtlsProvider = AppleCryptoDtlsProvider;

    CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
    }
}
