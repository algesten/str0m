//! OpenSSL implementation of cryptographic functions.
//! DTLS via OpenSSL's native DTLS implementation, or dimpl when `dtls13` feature is enabled.

#[cfg(not(feature = "dtls13"))]
mod dtls;
mod sha1;
mod sha256;
mod srtp;

#[cfg(feature = "dtls13")]
mod dtls_dimpl;

#[cfg(not(feature = "dtls13"))]
use dtls::OsslDtlsProvider;
#[cfg(feature = "dtls13")]
use dtls_dimpl::DimplDtlsProvider;
use sha1::OsslSha1HmacProvider;
use sha256::OsslSha256Provider;
use srtp::OsslSrtpProvider;
use str0m_proto::crypto::CryptoProvider;

#[macro_use]
extern crate tracing;

/// Create the default OpenSSL crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - SRTP for encrypted media (OpenSSL)
/// - SHA1-HMAC for STUN message integrity (OpenSSL)
/// - SHA-256 for certificate fingerprints (OpenSSL)
///
/// DTLS behaviour depends on features:
/// - Without `dtls13`: DTLS 1.2 via OpenSSL's native DTLS
/// - With `dtls13`: DTLS 1.2/1.3 via dimpl (auto-sensing)
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

    #[cfg(not(feature = "dtls13"))]
    {
        static DTLS: OsslDtlsProvider = OsslDtlsProvider;
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
