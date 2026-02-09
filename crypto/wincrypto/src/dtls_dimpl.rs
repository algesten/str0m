//! DTLS implementation using dimpl (DTLS 1.2 + 1.3) with aws-lc-rs backend.
//!
//! This module is compiled only when the `dtls13` feature is enabled.
//! It replaces the native Windows SChannel DTLS with dimpl, which supports both
//! DTLS 1.2 and DTLS 1.3 via auto-sensing.

use std::sync::Arc;
use std::time::Instant;

use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};
use str0m_proto::crypto::CryptoError;

// ============================================================================
// DTLS Provider Implementation
// ============================================================================

#[derive(Debug)]
pub(super) struct DimplDtlsProvider;

impl DtlsProvider for DimplDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        dimpl::certificate::generate_self_signed_certificate()
            .ok()
            .map(|cert| DtlsCert {
                certificate: cert.certificate,
                private_key: cert.private_key,
            })
    }

    fn new_dtls(&self, cert: &DtlsCert, now: Instant) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let dimpl_cert = dimpl::DtlsCertificate {
            certificate: cert.certificate.clone(),
            private_key: cert.private_key.clone(),
        };

        let mut builder = dimpl::Config::builder();
        if self.is_test() {
            builder = builder.dangerously_set_rng_seed(42);
        }

        let config = builder
            .build()
            .map_err(|e| CryptoError::Other(format!("dimpl config creation failed: {e}")))?;

        // Use new_13 for DTLS 1.3 (same as aws-lc-rs backend)
        let dtls = dimpl::Dtls::new_13(Arc::new(config), dimpl_cert, now);

        Ok(Box::new(DimplDtlsInstance { dtls }))
    }
}

// ============================================================================
// DTLS Instance Wrapper
// ============================================================================

struct DimplDtlsInstance {
    dtls: dimpl::Dtls,
}

impl std::fmt::Debug for DimplDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DimplDtlsInstance").finish()
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
