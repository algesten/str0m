//! OpenSSL implementation of cryptographic functions.

use super::{CryptoContext, CryptoError, SrtpProfile};

mod cert;
mod dtls;
mod io_buf;
mod sha1;
mod srtp;
mod stream;

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

pub(crate) fn create_crypto_context() -> CryptoContext {
    CryptoContext {
        create_dtls_identity_impl: cert::create_dtls_identity_impl,
        create_aes_128_cm_sha1_80_cipher_impl: srtp::Aes128CmSha1_80Impl::new,
        create_aead_aes_128_gcm_cipher_impl: srtp::AeadAes128GcmImpl::new,
        srtp_aes_128_ecb_round_impl: srtp::srtp_aes_128_ecb_round,
        sha1_hmac_impl: sha1::sha1_hmac,
    }
}

#[cfg(feature = "sha1")]
pub(super) mod sha1_crate {
    use super::{cert, srtp, CryptoContext};
    use hmac::Hmac;
    use hmac::Mac;
    use sha1::Sha1;

    pub(super) fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        let mut hmac = Hmac::<Sha1>::new_from_slice(key).expect("hmac to normalize size to 20");

        for payload in payloads {
            hmac.update(payload);
        }

        hmac.finalize().into_bytes().into()
    }

    pub(crate) fn create_crypto_context() -> CryptoContext {
        CryptoContext {
            create_dtls_identity_impl: cert::create_dtls_identity_impl,
            create_aes_128_cm_sha1_80_cipher_impl: srtp::Aes128CmSha1_80Impl::new,
            create_aead_aes_128_gcm_cipher_impl: srtp::AeadAes128GcmImpl::new,
            srtp_aes_128_ecb_round_impl: srtp::srtp_aes_128_ecb_round,
            sha1_hmac_impl: sha1_hmac,
        }
    }
}
