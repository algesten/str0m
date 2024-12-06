//! OpenSSL implementation of cryptographic functions.

use super::{CryptoError, SrtpProfile};

mod cert;
mod dtls;
mod io_buf;
mod srtp;
mod stream;

pub use cert::OsslDtlsCert as Cert;
pub use dtls::OsslDtlsImpl as Dtls;
pub use openssl::error::ErrorStack as Error;
pub use srtp::srtp_aes_128_ecb_round;
pub use srtp::OsslAeadAes128Gcm as AeadAes128Gcm;
pub use srtp::OsslAes128CmSha1_80 as Aes128CmSha1_80;

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

#[cfg(not(feature = "sha1"))]
pub fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    let key = PKey::hmac(key).expect("valid hmac key");
    let mut signer = Signer::new(MessageDigest::sha1(), &key).expect("valid signer");

    for payload in payloads {
        signer.update(payload).expect("signer update");
    }

    let mut hash = [0u8; 20];
    signer.sign(&mut hash).expect("sign to array");
    hash
}
