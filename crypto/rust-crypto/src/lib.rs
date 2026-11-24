//! RustCrypto implementation of cryptographic functions.
//! DTLS via dimpl with RustCrypto as crypto backend.

// Avoid rewriting existing code: nested conditions are often more readable than long if-chains.
#![allow(clippy::collapsible_if)]

mod dtls;
mod sha1;
mod sha256;
mod srtp;

use dtls::RustCryptoDtlsProvider;
use sha1::{RustCryptoSha1HmacProvider, RustCryptoSha1Provider};
use sha256::RustCryptoSha256Provider;
use srtp::RustCryptoSrtpProvider;
use str0m_proto::crypto::{CryptoError, CryptoProvider, SecureRandom};

/// Create the default RustCrypto crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2 for secure key exchange (using dimpl protocol + RustCrypto)
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
    static SRTP: RustCryptoSrtpProvider = RustCryptoSrtpProvider;
    static SHA1_HMAC: RustCryptoSha1HmacProvider = RustCryptoSha1HmacProvider;
    static SHA1: RustCryptoSha1Provider = RustCryptoSha1Provider;
    static SHA256: RustCryptoSha256Provider = RustCryptoSha256Provider;
    static DTLS: RustCryptoDtlsProvider = RustCryptoDtlsProvider;
    static RANDOM: RustCryptoSecureRandom = RustCryptoSecureRandom;

    CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha1_provider: &SHA1,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
        secure_random: Some(&RANDOM),
    }
}

/// Random bytes from the operating system, through dimpl's RustCrypto provider.
#[derive(Debug)]
struct RustCryptoSecureRandom;

impl SecureRandom for RustCryptoSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        dimpl::crypto::rust_crypto::default_provider()
            .secure_random
            .fill(buf)
            .map_err(|e| CryptoError::Other(format!("random fill failed: {e}")))
    }
}
