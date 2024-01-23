//! OpenSSL implementation of cryptographic functions.

use super::{CryptoError, SrtpProfile};

mod cert;
pub use cert::OsslDtlsCert;

mod io_buf;
mod stream;

mod dtls;
pub use dtls::OsslDtlsImpl;

impl SrtpProfile {
    // All the profiles we support, ordered from most preferred to least.
    pub(crate) const ALL: &'static [SrtpProfile] =
        &[SrtpProfile::AeadAes128Gcm, SrtpProfile::Aes128CmSha1_80];

    /// The length of keying material to extract from the DTLS session in bytes.
    #[rustfmt::skip]
    pub(crate) fn keying_material_len(&self) -> usize {
        match self {
            #[cfg(feature = "_internal_test_exports")]
            SrtpProfile::PassThrough => 0,
             // MASTER_KEY_LEN * 2 + MASTER_SALT * 2
             // TODO: This is a duplication of info that is held in srtp.rs, because we
             // don't want a dependency in that direction.
            SrtpProfile::Aes128CmSha1_80 => 16 * 2 + 14 * 2,
            SrtpProfile::AeadAes128Gcm   => 16 * 2 + 12 * 2,
        }
    }

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
