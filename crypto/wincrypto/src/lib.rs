//! Windows CNG implementation of cryptographic functions.
//! DTLS 1.2 and 1.3 via dimpl.

mod srtp;
use srtp::WinCryptoSrtpProvider;

mod sha1;
use sha1::WinCryptoSha1HmacProvider;

mod sha256;
use sha256::WinCryptoSha256Provider;

mod dimpl_provider;
mod dtls;
use dtls::WinCryptoDtlsProvider;

use str0m_proto::crypto::CryptoProvider;

pub use sys::WinCryptoError;

mod sys;

/// Create the default Windows CNG crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2 and 1.3 for secure key exchange (using dimpl + Windows CNG)
/// - SRTP for encrypted media (using Windows CNG)
/// - SHA1-HMAC for STUN message integrity (using Windows CNG)
/// - SHA-256 for certificate fingerprints (using Windows CNG)
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use str0m_wincrypto::default_provider;
///
/// let crypto_provider = Arc::new(default_provider());
/// // Pass this to str0m's RtcConfig when creating a WebRTC session
/// ```
pub fn default_provider() -> CryptoProvider {
    static SRTP: WinCryptoSrtpProvider = WinCryptoSrtpProvider;
    static SHA1_HMAC: WinCryptoSha1HmacProvider = WinCryptoSha1HmacProvider;
    static SHA256: WinCryptoSha256Provider = WinCryptoSha256Provider;
    static DTLS: WinCryptoDtlsProvider = WinCryptoDtlsProvider;

    CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
    }
}

/// Create the Windows CNG crypto provider used by the Dimpl DTLS backend.
///
/// This allows callers that need non-default Dimpl configuration to construct
/// `dimpl::Config` directly while retaining the Windows CNG implementation.
pub fn dimpl_crypto_provider() -> dimpl::crypto::CryptoProvider {
    dimpl_provider::default_provider()
}

#[cfg(test)]
mod tests {
    #[test]
    fn exposed_dimpl_provider_builds_config() {
        dimpl::Config::builder()
            .with_crypto_provider(super::dimpl_crypto_provider())
            .build()
            .expect("Windows CNG Dimpl provider should build a valid config");
    }
}
