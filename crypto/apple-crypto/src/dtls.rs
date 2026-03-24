//! DTLS implementation using dimpl with Apple CommonCrypto backend.

use dimpl::{Config, Dtls, DtlsCertificate};
use security_framework::access_control::SecAccessControl;
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};
use std::sync::Arc;
use std::time::Instant;
use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::DtlsVersion;
use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};

// Certificate Generation

fn generate_certificate_impl() -> Result<DtlsCert, CryptoError> {
    // Generate EC P-256 key pair using Security framework
    let mut options = GenerateKeyOptions::default();
    options.set_key_type(KeyType::ec());
    options.set_size_in_bits(256);
    let access_control = SecAccessControl::create_with_flags(0)
        .map_err(|e| CryptoError::Other(format!("Failed to create access control: {e}")))?;
    options.set_access_control(access_control);

    let private_key = SecKey::new(&options)
        .map_err(|e| CryptoError::Other(format!("Failed to generate key pair: {e}")))?;

    // Get the public key
    let public_key = private_key
        .public_key()
        .ok_or_else(|| CryptoError::Other("Failed to get public key".to_string()))?;

    // Export the private key using the safe wrapper.
    // For EC P-256, Apple exports: 04 || X (32 bytes) || Y (32 bytes) || D (32 bytes) = 97 bytes
    let private_key_data = private_key
        .external_representation()
        .ok_or_else(|| CryptoError::Other("Failed to export private key".into()))?;

    // Export the public key using the safe wrapper.
    // For EC P-256, Apple exports: 04 || X (32 bytes) || Y (32 bytes) = 65 bytes
    let public_key_data = public_key
        .external_representation()
        .ok_or_else(|| CryptoError::Other("Failed to export public key".into()))?;

    let mut serial = [0u8; 16];
    security_framework::random::SecRandom::default()
        .copy_bytes(&mut serial)
        .map_err(|_| CryptoError::Other("Failed to generate random serial".into()))?;
    serial[0] &= 0x7F; // Ensure positive

    let certificate = crate::cert::build_self_signed_certificate(
        "WebRTC",
        serial,
        public_key_data.bytes(),
        |tbs_certificate| {
            // Sign using ECDSA with SHA-256 directly with the generated key
            private_key
                .create_signature(
                    security_framework::key::Algorithm::ECDSASignatureMessageX962SHA256,
                    tbs_certificate,
                )
                .map_err(|e| CryptoError::Other(format!("Failed to sign: {e}")))
        },
    )?;

    // Apple exports private key as: 04 || X (32 bytes) || Y (32 bytes) || D (32 bytes) = 97 bytes for P-256
    // Apple exports public key as: 04 || X (32 bytes) || Y (32 bytes) = 65 bytes for P-256
    // We need just the D (private scalar) for SEC1 format
    let private_scalar = &private_key_data.bytes()[65..].try_into().map_err(|err| {
        CryptoError::Other(format!("Unexpected Apple private key contents: {err:?}"))
    })?;
    let private_key_der = crate::cert::build_pkcs8(private_scalar, public_key_data.bytes())?;

    Ok(DtlsCert {
        certificate,
        private_key: private_key_der,
    })
}

// DTLS Provider Implementation
#[derive(Debug)]
pub(crate) struct AppleCryptoDtlsProvider;

impl DtlsProvider for AppleCryptoDtlsProvider {
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

        // Create a dimpl Config with Apple CommonCrypto crypto provider
        let mut builder = Config::builder();
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
            DtlsVersion::Dtls12 => Dtls::new_12(config, dimpl_cert, now),
            DtlsVersion::Dtls13 => Dtls::new_13(config, dimpl_cert, now),
            DtlsVersion::Auto => Dtls::new_auto(config, dimpl_cert, now),
            _ => {
                return Err(CryptoError::Other(format!(
                    "Unsupported DTLS version: {dtls_version}"
                )));
            }
        };

        Ok(Box::new(AppleCryptoDtlsInstance { dtls }))
    }
}

// DTLS Instance Wrapper

struct AppleCryptoDtlsInstance {
    dtls: Dtls,
}

impl std::fmt::Debug for AppleCryptoDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleCryptoDtlsInstance").finish()
    }
}

impl DtlsInstance for AppleCryptoDtlsInstance {
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

#[cfg(test)]
mod tests {
    #[test]
    fn generate_self_signed_certificate() {
        let cert = super::generate_certificate_impl().unwrap();
        assert_eq!(150, cert.private_key.len());
    }
}
