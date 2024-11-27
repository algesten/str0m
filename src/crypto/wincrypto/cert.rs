use super::dtls::DtlsContextImpl;
use crate::crypto::{
    dtls::{DtlsContext, DtlsIdentity},
    CryptoContext, CryptoError, Fingerprint,
};
use std::sync::Arc;
use str0m_wincrypto::WinCryptoError;

pub(super) fn create_dtls_identity_impl(crypto_ctx: CryptoContext) -> Box<dyn DtlsIdentity> {
    let certificate = Arc::new(
        str0m_wincrypto::Certificate::new_self_signed("CN=WebRTC")
            .expect("Failed to create self-signed certificate"),
    );
    Box::new(DtlsIdentityImpl {
        certificate,
        crypto_ctx,
    })
}

#[derive(Clone, Debug)]
pub(super) struct DtlsIdentityImpl {
    crypto_ctx: CryptoContext,
    pub(super) certificate: Arc<str0m_wincrypto::Certificate>,
}

impl DtlsIdentity for DtlsIdentityImpl {
    fn fingerprint(&self) -> Fingerprint {
        create_fingerprint(&self.certificate).expect("Failed to calculate fingerprint")
    }

    fn create_context(&self) -> Result<Box<dyn DtlsContext>, CryptoError> {
        Ok(DtlsContextImpl::new(self)?)
    }

    fn boxed_clone(&self) -> Box<dyn DtlsIdentity> {
        Box::new(self.clone())
    }

    fn crypto_context(&self) -> CryptoContext {
        self.crypto_ctx
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
