//! DTLS implementation using dimpl with Windows CNG as crypto backend.

use std::sync::Arc;
use std::time::Instant;

use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::DtlsVersion;
use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};

use dimpl::{Config, Dtls, DtlsCertificate};

// ============================================================================
// DTLS Provider Implementation
// ============================================================================

#[derive(Debug)]
pub(crate) struct WinCryptoDtlsProvider;

impl DtlsProvider for WinCryptoDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        generate_certificate_impl().ok()
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let dimpl_cert = DtlsCertificate {
            certificate: cert.certificate.clone(),
            private_key: cert.private_key.clone(),
        };

        let mut builder = Config::builder();
        if self.is_test() {
            builder = builder.dangerously_set_rng_seed(42);
        }

        let config = builder
            .with_crypto_provider(crate::dimpl_provider::default_provider())
            .build()
            .map_err(|e| CryptoError::Other(format!("dimpl config creation failed: {e}")))?;

        let config = Arc::new(config);
        let dtls = match dtls_version {
            DtlsVersion::Dtls12 => Dtls::new_12(config, dimpl_cert, now),
            DtlsVersion::Dtls13 => Dtls::new_13(config, dimpl_cert, now),
            DtlsVersion::Auto => Dtls::new_auto(config, dimpl_cert, now),
            _ => {
                return Err(CryptoError::Other(format!(
                    "Unsupported DTLS version: {dtls_version}"
                )));
            }
        };

        Ok(Box::new(WinCryptoDtlsInstance { dtls }))
    }
}

struct WinCryptoDtlsInstance {
    dtls: Dtls,
}

impl std::fmt::Debug for WinCryptoDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinCryptoDtlsInstance").finish()
    }
}

impl DtlsInstance for WinCryptoDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.dtls.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        self.dtls.poll_output(buf)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.dtls.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.dtls.is_active()
    }
}

// ============================================================================
// Certificate Generation
// ============================================================================

fn generate_certificate_impl() -> Result<DtlsCert, CryptoError> {
    let cert = crate::sys::Certificate::new_self_signed(true, "cn=WebRTC").map_err(|e| {
        CryptoError::Other(format!("Failed to create self-signed certificate: {e}"))
    })?;

    let certificate = cert
        .get_der_bytes()
        .map_err(|e| CryptoError::Other(format!("Failed to get certificate DER bytes: {e}")))?;

    let private_key_der = cert
        .export_private_key_pkcs8_der()
        .map_err(|e| CryptoError::Other(format!("Failed to export private key as PKCS#8: {e}")))?;

    Ok(DtlsCert {
        certificate,
        private_key: private_key_der,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn generate_self_signed_certificate() {
        let cert = super::generate_certificate_impl().unwrap();
        assert_eq!(165, cert.private_key.len());
    }
}
