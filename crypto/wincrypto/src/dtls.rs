//! DTLS provider routing.
//!
//! When the `dtls12` feature is enabled (default), uses Windows SChannel for DTLS 1.2 only.
//! When disabled, uses dimpl with Windows CNG crypto for DTLS 1.2/1.3/Auto.

use std::time::Instant;

use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::DtlsVersion;
use str0m_proto::crypto::dtls::{DtlsCert, DtlsInstance, DtlsProvider};

#[derive(Debug)]
pub(crate) struct WinCryptoDtlsProvider;

impl DtlsProvider for WinCryptoDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        #[cfg(feature = "dtls12")]
        {
            crate::schannel_dtls::generate_certificate()
        }
        #[cfg(not(feature = "dtls12"))]
        {
            crate::dimpl_dtls::generate_certificate()
        }
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        #[cfg(feature = "dtls12")]
        {
            let _ = now; // SChannel manages timeouts internally
            crate::schannel_dtls::new_dtls(cert, dtls_version)
        }
        #[cfg(not(feature = "dtls12"))]
        {
            crate::dimpl_dtls::new_dtls(self, cert, now, dtls_version)
        }
    }
}
