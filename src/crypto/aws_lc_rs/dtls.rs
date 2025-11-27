//! DTLS implementation using dimpl with AWS-LC-RS backend.

use std::sync::Arc;
use std::time::Instant;

use crate::crypto::error::CryptoError;
use crate::crypto::provider::{DimplError, DtlsInstance, DtlsOutput, DtlsProvider};
use crate::crypto::DtlsCert;

// ============================================================================
// DTLS Provider Implementation
// ============================================================================

#[derive(Debug)]
pub(super) struct AwsLcRsDtlsProvider;

impl DtlsProvider for AwsLcRsDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        // Use dimpl's rcgen-based certificate generation (with aws-lc-rs backend)
        dimpl::certificate::generate_self_signed_certificate()
            .ok()
            .map(|cert| DtlsCert {
                certificate: cert.certificate,
                private_key: cert.private_key,
            })
    }

    fn new_dtls(&self, cert: &DtlsCert) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let dimpl_cert = dimpl::DtlsCertificate {
            certificate: cert.certificate.clone(),
            private_key: cert.private_key.clone(),
        };

        // Create a default dimpl Config with AWS-LC-RS crypto provider
        let config = dimpl::Config::builder()
            .build()
            .map_err(|e| CryptoError::Other(format!("dimpl config creation failed: {}", e)))?;

        let dtls = dimpl::Dtls::new(Arc::new(config), dimpl_cert);

        Ok(Box::new(AwsLcRsDtlsInstance { dtls }))
    }
}

// ============================================================================
// DTLS Instance Wrapper
// ============================================================================

struct AwsLcRsDtlsInstance {
    dtls: dimpl::Dtls,
}

impl std::fmt::Debug for AwsLcRsDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsLcRsDtlsInstance").finish()
    }
}

impl DtlsInstance for AwsLcRsDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.dtls.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DimplError> {
        self.dtls.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        self.dtls.poll_output(buf)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DimplError> {
        self.dtls.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DimplError> {
        self.dtls.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.dtls.is_active()
    }
}
