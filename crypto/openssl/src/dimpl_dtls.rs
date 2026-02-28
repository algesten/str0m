//! DTLS implementation using dimpl with OpenSSL crypto backend.
//!
//! Supports DTLS 1.2, 1.3, and Auto negotiation.

use std::sync::Arc;
use std::time::Instant;

use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};
use str0m_proto::crypto::{CryptoError, DtlsVersion};

// ============================================================================
// Dimpl DTLS Instance Wrapper
// ============================================================================

struct DimplDtlsInstance {
    dtls: dimpl::Dtls,
}

impl std::fmt::Debug for DimplDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DimplDtlsInstance")
            .field("is_active", &self.dtls.is_active())
            .finish()
    }
}

impl DtlsInstance for DimplDtlsInstance {
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
// Public API
// ============================================================================

pub(crate) fn generate_certificate() -> Option<DtlsCert> {
    super::dtls::generate_certificate_impl().ok()
}

pub(crate) fn new_dtls(
    provider: &impl DtlsProvider,
    cert: &DtlsCert,
    now: Instant,
    dtls_version: DtlsVersion,
) -> Result<Box<dyn DtlsInstance>, CryptoError> {
    let dimpl_cert = dimpl::DtlsCertificate {
        certificate: cert.certificate.clone(),
        private_key: cert.private_key.clone(),
    };

    let mut builder = dimpl::Config::builder();
    if provider.is_test() {
        // We need the DTLS impl to be deterministic for the BWE tests.
        builder = builder.dangerously_set_rng_seed(42);
    }

    let config = builder
        .with_crypto_provider(crate::dimpl_provider::default_provider())
        .build()
        .map_err(|e| CryptoError::Other(format!("dimpl config creation failed: {e}")))?;

    let config = Arc::new(config);
    let dtls = match dtls_version {
        DtlsVersion::Dtls12 => dimpl::Dtls::new_12(config, dimpl_cert, now),
        DtlsVersion::Dtls13 => dimpl::Dtls::new_13(config, dimpl_cert, now),
        DtlsVersion::Auto => dimpl::Dtls::new_auto(config, dimpl_cert, now),
        _ => {
            return Err(CryptoError::Other(format!(
                "Unknown DTLS version: {dtls_version}"
            )));
        }
    };

    Ok(Box::new(DimplDtlsInstance { dtls }))
}
