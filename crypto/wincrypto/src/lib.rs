//! Windows SChannel + CNG implementation of cryptographic functions.
//! DTLS via Windows SChannel, or dimpl when `dtls13` feature is enabled.

#[macro_use]
extern crate tracing;

mod srtp;
use srtp::WinCryptoSrtpProvider;

mod sha1;
use sha1::WinCryptoSha1HmacProvider;

mod sha256;
use sha256::WinCryptoSha256Provider;

#[cfg(not(feature = "dtls13"))]
mod dtls;
#[cfg(not(feature = "dtls13"))]
use dtls::WinCryptoDtlsProvider;

#[cfg(feature = "dtls13")]
mod dtls_dimpl;
#[cfg(feature = "dtls13")]
use dtls_dimpl::DimplDtlsProvider;

use str0m_proto::crypto::CryptoProvider;

pub use sys::WinCryptoError;

mod sys;

/// Create the default Windows CNG/SChannel crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - SRTP for encrypted media (Windows CNG)
/// - SHA1-HMAC for STUN message integrity (Windows CNG)
/// - SHA-256 for certificate fingerprints (Windows CNG)
///
/// DTLS behaviour depends on features:
/// - Without `dtls13`: DTLS 1.2 via Windows SChannel
/// - With `dtls13`: DTLS 1.2/1.3 via dimpl (auto-sensing)
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

    #[cfg(not(feature = "dtls13"))]
    {
        static DTLS: WinCryptoDtlsProvider = WinCryptoDtlsProvider;
        CryptoProvider {
            srtp_provider: &SRTP,
            sha1_hmac_provider: &SHA1_HMAC,
            sha256_provider: &SHA256,
            dtls_provider: &DTLS,
        }
    }

    #[cfg(feature = "dtls13")]
    {
        static DTLS: DimplDtlsProvider = DimplDtlsProvider;
        CryptoProvider {
            srtp_provider: &SRTP,
            sha1_hmac_provider: &SHA1_HMAC,
            sha256_provider: &SHA256,
            dtls_provider: &DTLS,
        }
    }
}
