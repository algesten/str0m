//! OpenSSL cryptographic provider implementation for str0m.
//!
//! This module provides the OpenSSL-based cryptographic backend for str0m,
//! handling SRTP encryption and SHA1-HMAC for STUN.
//!
//! DTLS uses dimpl for the protocol implementation, with OpenSSL providing
//! the underlying TLS transport.
//!
//! # Feature Flag
//!
//! This module is only available when the `openssl` feature is enabled.
//! The `openssl` feature is included in the default features.

mod dtls;
mod sha1;
mod sha256;
mod srtp;

use super::CryptoProvider;
use dtls::OsslDtlsProvider;
use sha1::OsslSha1HmacProvider;
use sha256::OsslSha256Provider;
use srtp::OsslSrtpProvider;

/// Create the default OpenSSL crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2 for secure key exchange (using dimpl protocol + OpenSSL TLS)
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
    static SRTP: OsslSrtpProvider = OsslSrtpProvider;
    static SHA1_HMAC: OsslSha1HmacProvider = OsslSha1HmacProvider;
    static SHA256: OsslSha256Provider = OsslSha256Provider;
    static DTLS: OsslDtlsProvider = OsslDtlsProvider;

    CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
    }
}
