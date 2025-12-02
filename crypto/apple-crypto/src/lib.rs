//! Apple CommonCrypto cryptographic provider implementation for str0m.
//!
//! This crate provides the Apple CommonCrypto/Security framework-based cryptographic
//! backend for str0m, handling SRTP encryption and SHA1-HMAC for STUN.
//!
//! DTLS uses dimpl for the protocol implementation, with Apple CommonCrypto providing
//! the underlying cryptographic operations.
//!
//! # Platform Support
//!
//! This crate only works on Apple platforms (macOS, iOS, tvOS, watchOS).
//!
//! # Usage
//!
#![allow(clippy::redundant_pub_crate)]
//! ```ignore
//! use str0m::Rtc;
//! use str0m_apple_crypto::default_provider;
//!
//! // Install as process-wide default
//! default_provider().install_process_default();
//!
//! // Or use with RtcConfig
//! let rtc = Rtc::builder()
//!     .set_crypto_provider(default_provider())
//!     .build();
//! ```
//!
//! # Supported SRTP Profiles
//!
//! - `SRTP_AES128_CM_SHA1_80`
//! - `SRTP_AEAD_AES_128_GCM`
//! - `SRTP_AEAD_AES_256_GCM`

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
