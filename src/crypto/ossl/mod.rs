//! OpenSSL implementation of cryptographic functions.

use super::{CryptoError, SrtpProfile};

mod cert;
pub use cert::OsslDtlsCert;

mod io_buf;
mod stream;

mod dtls;
pub use dtls::OsslDtlsImpl;

mod srtp;
pub use srtp::OsslSrtpCryptoImpl;

impl SrtpProfile {
    /// What this profile is called in OpenSSL parlance.
    pub(crate) fn openssl_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "_internal_test_exports")]
            SrtpProfile::PassThrough => "NULL",
            SrtpProfile::Aes128CmSha1_80 => "SRTP_AES128_CM_SHA1_80",
            SrtpProfile::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
        }
    }
}
