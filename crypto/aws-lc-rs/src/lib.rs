//! AWS-LC-RS implementation of cryptographic functions.
//! DTLS via dimpl with AWS-LC-RS as crypto backend.

mod dtls;
mod sha1;
mod sha256;
mod srtp;

use dtls::AwsLcRsDtlsProvider;
use sha1::AwsLcRsSha1HmacProvider;
use sha256::AwsLcRsSha256Provider;
use srtp::AwsLcRsSrtpProvider;
use str0m_proto::crypto::CryptoProvider;

/// Create the default AWS-LC-RS crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2 for secure key exchange (using dimpl protocol + AWS-LC-RS)
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
    static SRTP: AwsLcRsSrtpProvider = AwsLcRsSrtpProvider;
    static SHA1_HMAC: AwsLcRsSha1HmacProvider = AwsLcRsSha1HmacProvider;
    static SHA256: AwsLcRsSha256Provider = AwsLcRsSha256Provider;
    static DTLS: AwsLcRsDtlsProvider = AwsLcRsDtlsProvider;

    CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
    }
}
