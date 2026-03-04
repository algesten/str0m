//! DTLS implementation using dimpl with Android JNI crypto backend.

use std::sync::Arc;
use std::time::Instant;

use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};
use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::DtlsVersion;

use crate::jni_crypto;

// Certificate Generation

fn generate_certificate_impl() -> Result<DtlsCert, CryptoError> {
    // Generate EC P-256 key pair using Android KeyPairGenerator
    let key_pair = jni_crypto::generate_ec_key_pair_p256()?;

    // Create a self-signed certificate
    let certificate =
        build_self_signed_cert(&key_pair.public_key_bytes, &key_pair.private_key_der)?;

    Ok(DtlsCert {
        certificate,
        private_key: key_pair.private_key_der,
    })
}

/// Build a minimal self-signed X.509 v3 certificate
fn build_self_signed_cert(
    public_key_bytes: &[u8],
    private_key_der: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Build TBSCertificate
    let tbs = build_tbs_certificate(public_key_bytes)?;

    // Sign the TBS certificate using ECDSA with SHA-256
    let signature = jni_crypto::ecdsa_sign_sha256(private_key_der, &tbs)?;

    // Encode the full certificate
    let ecdsa_with_sha256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
    let sig_algorithm = encode_algorithm_identifier(ecdsa_with_sha256_oid);

    // Signature as BIT STRING (prepend 0x00 for no unused bits)
    let signature_bits = encode_bit_string(&signature);

    // Full certificate SEQUENCE
    let mut cert_content = Vec::new();
    cert_content.extend_from_slice(&tbs);
    cert_content.extend_from_slice(&sig_algorithm);
    cert_content.extend_from_slice(&signature_bits);

    Ok(encode_sequence(&cert_content))
}

fn build_tbs_certificate(public_key_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut tbs = Vec::new();

    // Version: v3 (encoded as [0] EXPLICIT INTEGER 2)
    let version = encode_explicit_tag(0, &encode_integer(&[2]));
    tbs.extend_from_slice(&version);

    // Serial number (random)
    let mut serial = [0u8; 16];
    jni_crypto::secure_random(&mut serial)?;
    serial[0] &= 0x7F; // Ensure positive
    tbs.extend_from_slice(&encode_integer(&serial));

    // Signature algorithm: ecdsa-with-SHA256
    let ecdsa_with_sha256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    tbs.extend_from_slice(&encode_algorithm_identifier(ecdsa_with_sha256_oid));

    // Issuer: CN=WebRTC
    let issuer = encode_name("WebRTC");
    tbs.extend_from_slice(&issuer);

    // Validity: 1 year from now
    let validity = encode_validity();
    tbs.extend_from_slice(&validity);

    // Subject: CN=WebRTC (same as issuer for self-signed)
    tbs.extend_from_slice(&issuer);

    // Subject Public Key Info
    let spki = encode_ec_public_key_info(public_key_bytes)?;
    tbs.extend_from_slice(&spki);

    Ok(encode_sequence(&tbs))
}

fn encode_sequence(content: &[u8]) -> Vec<u8> {
    encode_tag(0x30, content)
}

fn encode_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    encode_length(content.len(), &mut result);
    result.extend_from_slice(content);
    result
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

fn encode_integer(value: &[u8]) -> Vec<u8> {
    // Skip leading zeros but keep at least one byte
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0 {
        start += 1;
    }

    let value = &value[start..];

    // If high bit is set, prepend 0x00
    if value[0] & 0x80 != 0 {
        let mut content = vec![0x00];
        content.extend_from_slice(value);
        encode_tag(0x02, &content)
    } else {
        encode_tag(0x02, value)
    }
}

fn encode_explicit_tag(tag_num: u8, content: &[u8]) -> Vec<u8> {
    encode_tag(0xA0 | tag_num, content)
}

fn encode_oid(oid_bytes: &[u8]) -> Vec<u8> {
    encode_tag(0x06, oid_bytes)
}

fn encode_algorithm_identifier(oid_bytes: &[u8]) -> Vec<u8> {
    let oid = encode_oid(oid_bytes);
    encode_sequence(&oid)
}

fn encode_name(cn: &str) -> Vec<u8> {
    // CN OID: 2.5.4.3
    let cn_oid = &[0x55, 0x04, 0x03];
    let oid = encode_oid(cn_oid);
    let value = encode_tag(0x0C, cn.as_bytes()); // UTF8String
    let attr_type_value = encode_sequence(&[oid, value].concat());
    let rdn = encode_tag(0x31, &attr_type_value); // SET
    encode_sequence(&rdn)
}

fn encode_validity() -> Vec<u8> {
    // Use GeneralizedTime for dates
    // Not before: now (using a reasonable fixed date for simplicity)
    // Not after: 1 year from now
    // Format: YYYYMMDDHHMMSSZ
    let not_before = b"20240101000000Z";
    let not_after = b"20251231235959Z";

    let nb = encode_tag(0x18, not_before); // GeneralizedTime
    let na = encode_tag(0x18, not_after);

    encode_sequence(&[nb, na].concat())
}

fn encode_ec_public_key_info(public_key_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // AlgorithmIdentifier for EC public key
    // OID: 1.2.840.10045.2.1 (ecPublicKey)
    let ec_public_key_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    // OID: 1.2.840.10045.3.1.7 (prime256v1/secp256r1)
    let prime256v1_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let algorithm =
        encode_sequence(&[encode_oid(ec_public_key_oid), encode_oid(prime256v1_oid)].concat());

    // Public key as BIT STRING
    let public_key_bits = encode_bit_string(public_key_bytes);

    Ok(encode_sequence(&[algorithm, public_key_bits].concat()))
}

fn encode_bit_string(data: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // No unused bits
    content.extend_from_slice(data);
    encode_tag(0x03, &content)
}

// DTLS Provider Implementation

use dimpl::{Config, Dtls, DtlsCertificate};

#[derive(Debug)]
pub(crate) struct AndroidCryptoDtlsProvider;

impl DtlsProvider for AndroidCryptoDtlsProvider {
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

        // Create a dimpl Config with Android JNI crypto provider
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
                )))
            }
        };

        Ok(Box::new(AndroidCryptoDtlsInstance { dtls }))
    }
}

// DTLS Instance Wrapper

struct AndroidCryptoDtlsInstance {
    dtls: Dtls,
}

impl std::fmt::Debug for AndroidCryptoDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCryptoDtlsInstance").finish()
    }
}

impl DtlsInstance for AndroidCryptoDtlsInstance {
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
mod test {
    use super::*;

    #[test]
    fn test_generate_certificate() {
        let cert = generate_certificate_impl().expect("certificate generation failed");

        // Certificate should be non-empty DER starting with SEQUENCE tag (0x30)
        assert!(!cert.certificate.is_empty(), "certificate is empty");
        assert_eq!(
            cert.certificate[0], 0x30,
            "certificate DER does not start with SEQUENCE tag"
        );

        // Private key should be non-empty DER (PKCS#8 starts with SEQUENCE tag)
        assert!(!cert.private_key.is_empty(), "private key is empty");
        assert_eq!(
            cert.private_key[0], 0x30,
            "private key DER does not start with SEQUENCE tag"
        );

        // Compute SHA-256 fingerprint (what str0m uses for DTLS verification)
        let fingerprint =
            jni_crypto::sha256(&cert.certificate).expect("SHA-256 fingerprint failed");
        assert_eq!(fingerprint.len(), 32);

        // Generating a second certificate should produce different keys
        let cert2 = generate_certificate_impl().expect("second certificate generation failed");
        assert_ne!(
            cert.private_key, cert2.private_key,
            "two generated certificates should have different private keys"
        );
        assert_ne!(
            cert.certificate, cert2.certificate,
            "two generated certificates should differ"
        );
    }
}
