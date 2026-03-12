//! DTLS implementation using dimpl with Apple CommonCrypto backend.

use std::time::Instant;

use security_framework::access_control::SecAccessControl;
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};

use security_framework::random::SecRandom;
use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::DtlsVersion;
use str0m_proto::crypto::dtls::{DtlsCert, DtlsInstance, DtlsProvider};

use crate::dimpl_provider::common::{build_pkcs8, build_self_signed_certificate};

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
    SecRandom::default()
        .copy_bytes(&mut serial)
        .map_err(|_| CryptoError::Other("Failed to generate random serial".into()))?;
    serial[0] &= 0x7F; // Ensure positive

    let public_key_bytes = public_key_data.bytes().to_vec();
    let certificate =
        build_self_signed_certificate("WebRTC", serial, &public_key_bytes, |tbs_certificate| {
            // Sign using ECDSA with SHA-256 directly with the generated key
            private_key
                .create_signature(
                    security_framework::key::Algorithm::ECDSASignatureMessageX962SHA256,
                    tbs_certificate,
                )
                .map_err(|e| CryptoError::Other(format!("Failed to sign: {e}")))
        })?;

    // Apple exports private key as: 04 || X (32 bytes) || Y (32 bytes) || D (32 bytes) = 97 bytes for P-256
    // Apple exports public key as: 04 || X (32 bytes) || Y (32 bytes) = 65 bytes for P-256
    // We need just the D (private scalar) for SEC1 format
    let private_scalar = &private_key_data.bytes()[65..].try_into().map_err(|err| {
        CryptoError::Other(format!("Unexpected Apple private key contents: {err:?}"))
    })?;
    let private_key_der = build_pkcs8(private_scalar, &public_key_bytes)?;

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
        crate::dimpl_provider::common::DimplCryptoDtlsInstance::try_new(
            "AppleCryptoDtlsInstance",
            cert,
            now,
            dtls_version,
            self.is_test(),
        )
    }
}
