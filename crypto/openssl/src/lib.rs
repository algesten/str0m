//! OpenSSL implementation of cryptographic functions.
//! DTLS via OpenSSL's native DTLS implementation.

// Avoid rewriting existing code: nested conditions are often more readable than long if-chains.
#![allow(clippy::collapsible_if)]

mod cert;
#[cfg(feature = "dimpl")]
mod dimpl_provider;
#[cfg_attr(feature = "dimpl", path = "dtls_dimpl.rs")]
#[cfg_attr(not(feature = "dimpl"), path = "dtls_ossl.rs")]
mod dtls;
mod sha1;
mod sha256;
mod srtp;

use dtls::OsslDtlsProvider;
use sha1::{OsslSha1HmacProvider, OsslSha1Provider};
use sha256::OsslSha256Provider;
use srtp::OsslSrtpProvider;
use str0m_proto::crypto::CryptoProvider;

#[cfg(not(feature = "dimpl"))]
#[macro_use]
extern crate tracing;

/// Create the default OpenSSL crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2 for secure key exchange (using dimpl protocol + OpenSSL TLS)
/// - SRTP for encrypted media
/// - SHA1-HMAC for STUN message integrity
/// - SHA-1 and SHA-256 for certificate fingerprints
///
/// # Supported SRTP Profiles
///
/// - `SRTP_AES128_CM_SHA1_80`
/// - `SRTP_AEAD_AES_128_GCM`
/// - `SRTP_AEAD_AES_256_GCM`
pub fn default_provider() -> CryptoProvider {
    static SRTP: OsslSrtpProvider = OsslSrtpProvider;
    static SHA1_HMAC: OsslSha1HmacProvider = OsslSha1HmacProvider;
    static SHA1: OsslSha1Provider = OsslSha1Provider;
    static SHA256: OsslSha256Provider = OsslSha256Provider;
    static DTLS: OsslDtlsProvider = OsslDtlsProvider;

    CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha1_provider: &SHA1,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
    }
}
