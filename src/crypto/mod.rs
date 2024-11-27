#![allow(unreachable_patterns)]

use std::io;
use thiserror::Error;

#[cfg(feature = "openssl")]
mod ossl;

#[cfg(feature = "wincrypto")]
mod wincrypto;

mod dtls;
pub use dtls::{DtlsCert, DtlsEvent};
pub(crate) use dtls::{DtlsContext, DtlsIdentity};

mod finger;
pub use finger::Fingerprint;

mod keying;
pub use keying::KeyingMaterial;

mod srtp;
pub use srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80, SrtpProfile};

#[cfg(not(any(feature = "openssl", feature = "wincrypto")))]
compile_error!("either `openssl` or `wincrypto` must be enabled");

/// Errors that can arise in DTLS.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Some error from OpenSSL layer (used for DTLS).
    #[error("{0}")]
    #[cfg(feature = "openssl")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    /// Some error from OpenSSL layer (used for DTLS).
    #[error("{0}")]
    #[cfg(feature = "wincrypto")]
    WinCrypto(#[from] wincrypto::WinCryptoError),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CryptoProviderId {
    #[cfg(feature = "openssl")]
    OpenSsl,
    #[cfg(all(feature = "openssl", feature = "sha1"))]
    OpenSslWithSha1Crate,
    #[cfg(feature = "wincrypto")]
    WinCrypto,
}

#[cfg(feature = "openssl")]
impl Default for CryptoProviderId {
    fn default() -> Self {
        if cfg!(feature = "sha1") {
            CryptoProviderId::OpenSslWithSha1Crate
        } else {
            CryptoProviderId::OpenSsl
        }
    }
}

impl From<CryptoProviderId> for CryptoProvider {
    fn from(value: CryptoProviderId) -> Self {
        match value {
            #[cfg(feature = "openssl")]
            CryptoProviderId::OpenSsl => ossl::create_crypto_provider(),
            #[cfg(all(feature = "openssl", feature = "sha1"))]
            CryptoProviderId::OpenSslWithSha1Crate => ossl::sha1_crate::create_crypto_provider(),
            #[cfg(feature = "wincrypto")]
            CryptoProviderId::WinCrypto => wincrypto::create_crypto_provider(),
        }
    }
}

/// RTP/SRTP ciphers and hashes
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CryptoProvider {
    pub(crate) crypto_provider_id: CryptoProviderId,
    pub(super) create_dtls_identity_impl: fn(CryptoProvider) -> Box<dyn DtlsIdentity>,
    pub(super) create_aes_128_cm_sha1_80_cipher_impl:
        fn(&aes_128_cm_sha1_80::AesKey, bool) -> Box<dyn aes_128_cm_sha1_80::CipherCtx>,
    pub(super) create_aead_aes_128_gcm_cipher_impl:
        fn(&aead_aes_128_gcm::AeadKey, bool) -> Box<dyn aead_aes_128_gcm::CipherCtx>,
    pub(super) srtp_aes_128_ecb_round_impl: fn(&[u8], &[u8], &mut [u8]) -> (),
    pub(super) sha1_hmac_impl: fn(&[u8], &[&[u8]]) -> [u8; 20],
}

impl CryptoProvider {
    pub(super) fn create_dtls_identity(&self) -> Box<dyn DtlsIdentity> {
        (self.create_dtls_identity_impl)(*self)
    }

    pub(crate) fn create_aes_128_cm_sha1_80_cipher(
        &self,
        key: &aes_128_cm_sha1_80::AesKey,
        encrypt: bool,
    ) -> Box<dyn aes_128_cm_sha1_80::CipherCtx> {
        (self.create_aes_128_cm_sha1_80_cipher_impl)(key, encrypt)
    }

    pub(crate) fn create_aead_aes_128_gcm_cipher(
        &self,
        key: &aead_aes_128_gcm::AeadKey,
        encrypt: bool,
    ) -> Box<dyn aead_aes_128_gcm::CipherCtx> {
        (self.create_aead_aes_128_gcm_cipher_impl)(key, encrypt)
    }

    pub(crate) fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        (self.srtp_aes_128_ecb_round_impl)(key, input, output)
    }

    pub(crate) fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        (self.sha1_hmac_impl)(key, payloads)
    }
}
