//! Windows SChannel + CNG implementation of cryptographic functions.
//! DTLS via Windows SChannel.

#[cfg(not(feature = "prefer_dimpl"))]
#[macro_use]
extern crate tracing;

mod srtp;
use srtp::WinCryptoSrtpProvider;

mod sha1;
use sha1::WinCryptoSha1HmacProvider;

mod sha256;
use sha256::WinCryptoSha256Provider;

#[cfg(feature = "prefer_dimpl")]
mod dimpl_provider;
#[cfg_attr(feature = "prefer_dimpl", path = "dtls_dimpl.rs")]
#[cfg_attr(not(feature = "prefer_dimpl"), path = "dtls_schannel.rs")]
mod dtls;
use dtls::WinCryptoDtlsProvider;

use str0m_proto::crypto::CryptoProvider;

pub use sys::WinCryptoError;

mod sys;

/// Create the default Windows CNG/SChannel crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2 for secure key exchange (using Windows SChannel)
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
