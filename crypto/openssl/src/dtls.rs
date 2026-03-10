//! DTLS implementation using OpenSSL via dimpl.

use std::sync::Arc;
use std::time::Instant;

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::X509Builder;
use openssl::x509::X509NameBuilder;
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

use str0m_proto::crypto::dtls::DtlsImplError;
use str0m_proto::crypto::dtls::{DtlsCert, DtlsInstance, DtlsOutput, DtlsProvider};
use str0m_proto::crypto::{CryptoError, DtlsVersion};

// ============================================================================
// DTLS Provider Implementation
// ============================================================================

pub(super) struct OsslDtlsProvider;

impl std::fmt::Debug for OsslDtlsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslDtlsProvider").finish()
    }
}

impl DtlsProvider for OsslDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        generate_certificate_impl().ok()
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let dimpl_cert = dimpl::DtlsCertificate {
            certificate: cert.certificate.clone(),
            private_key: cert.private_key.clone(),
        };

        let mut builder = dimpl::Config::builder();
        if self.is_test() {
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
}

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

fn generate_certificate_impl() -> Result<DtlsCert, CryptoError> {
    // Generate EC key pair using P-256 curve
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    // Build the X509 certificate
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?; // X509 v3

    // Generate random serial number
    let mut serial = BigNum::new()?;
    serial.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
    builder.set_serial_number(serial.to_asn1_integer()?.as_ref())?;

    // Set validity period (1 year)
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Set subject name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", "WebRTC")?;
    let name = name_builder.build();
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;

    builder.set_pubkey(&pkey)?;

    // Add extensions
    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(basic_constraints)?;

    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_encipherment()
        .build()?;
    builder.append_extension(key_usage)?;

    let ext_key_usage = ExtendedKeyUsage::new()
        .server_auth()
        .client_auth()
        .build()?;
    builder.append_extension(ext_key_usage)?;

    // Sign the certificate
    builder.sign(&pkey, MessageDigest::sha256())?;

    let cert = builder.build();

    // Convert to DER format
    let certificate = cert.to_der()?;
    let private_key = pkey.private_key_to_der()?;

    Ok(DtlsCert {
        certificate,
        private_key,
    })
}
