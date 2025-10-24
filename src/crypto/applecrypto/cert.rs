use super::AppleCryptoDtls;
use super::CryptoError;
use crate::crypto::dtls::{DtlsCertOptions, DtlsPKeyType};
use crate::crypto::Fingerprint;
use std::sync::Arc;
use str0m_applecrypto::AppleCryptoError;

#[derive(Clone, Debug)]
pub struct AppleCryptoDtlsCert {
    pub(crate) certificate: Arc<str0m_applecrypto::Certificate>,
}

impl AppleCryptoDtlsCert {
    pub fn new(options: DtlsCertOptions) -> Self {
        let use_ec_dsa_keys = match options.pkey_type {
            DtlsPKeyType::Rsa2048 => false,
            DtlsPKeyType::EcDsaP256 => true,
        };

        let certificate = Arc::new(
            str0m_applecrypto::Certificate::new_self_signed(
                use_ec_dsa_keys,
                &format!("CN={}", options.common_name),
            )
            .expect("Failed to create self-signed certificate"),
        );
        Self { certificate }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        create_fingerprint(&self.certificate).expect("Failed to calculate fingerprint")
    }

    pub(crate) fn new_dtls_impl(&self) -> Result<AppleCryptoDtls, CryptoError> {
        AppleCryptoDtls::new(self.clone())
    }
}

pub(super) fn create_fingerprint(
    certificate: &str0m_applecrypto::Certificate,
) -> Result<Fingerprint, AppleCryptoError> {
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
