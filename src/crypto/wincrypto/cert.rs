use super::CryptoError;
use super::WinCryptoDtls;
use crate::crypto::dtls::DTLS_CERT_IDENTITY;
use crate::crypto::Fingerprint;
use std::sync::Arc;
use str0m_wincrypto::WinCryptoError;

#[derive(Clone, Debug)]
pub struct WinCryptoDtlsCert {
    pub(crate) certificate: Arc<str0m_wincrypto::Certificate>,
}

impl WinCryptoDtlsCert {
    pub fn new() -> Self {
        let certificate = Arc::new(
            str0m_wincrypto::Certificate::new_self_signed(&format!("CN={}", DTLS_CERT_IDENTITY))
                .expect("Failed to create self-signed certificate"),
        );
        Self { certificate }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        create_fingerprint(&self.certificate).expect("Failed to calculate fingerprint")
    }

    pub(crate) fn new_dtls_impl(&self) -> Result<WinCryptoDtls, CryptoError> {
        WinCryptoDtls::new(self.clone())
    }
}

pub(super) fn create_fingerprint(
    certificate: &str0m_wincrypto::Certificate,
) -> Result<Fingerprint, WinCryptoError> {
    certificate
        .sha256_fingerprint()
        .map(|f| create_sha256_fingerprint(&f))
}

pub(super) fn create_sha256_fingerprint(bytes: &[u8; 32]) -> Fingerprint {
    Fingerprint {
        hash_func: "sha-256".into(),
        bytes: bytes.to_vec(),
    }
}
