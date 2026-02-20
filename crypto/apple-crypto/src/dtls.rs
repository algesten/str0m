//! DTLS implementation using dimpl with Apple CommonCrypto backend.

use std::sync::Arc;
use std::time::Instant;

use security_framework::access_control::SecAccessControl;
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};

use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};
use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::DtlsVersion;

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

    let private_key_bytes = private_key_data.bytes().to_vec();
    let public_key_bytes = public_key_data.bytes().to_vec();

    // Create a simple self-signed certificate - pass the SecKey directly for signing
    let certificate = build_self_signed_cert(&public_key_bytes, &private_key)?;

    // Apple exports private key as: 04 || X || Y || D (97 bytes for P-256)
    // We need to wrap this into proper PKCS#8 with SEC1 ECPrivateKey that includes public key
    let private_key_der = wrap_ec_private_key_pkcs8(&private_key_bytes, &public_key_bytes)?;

    Ok(DtlsCert {
        certificate,
        private_key: private_key_der,
    })
}

/// Build a minimal self-signed X.509 v3 certificate
fn build_self_signed_cert(
    public_key_bytes: &[u8],
    private_key: &SecKey,
) -> Result<Vec<u8>, CryptoError> {
    // Build TBSCertificate
    let tbs = build_tbs_certificate(public_key_bytes)?;

    // Sign the TBS certificate using the private key directly
    let signature = sign_with_ecdsa_sha256(&tbs, private_key)?;

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
    use security_framework::random::SecRandom;
    SecRandom::default()
        .copy_bytes(&mut serial)
        .map_err(|_| CryptoError::Other("Failed to generate random serial".into()))?;
    serial[0] &= 0x7F; // Ensure positive
    tbs.extend_from_slice(&encode_integer(&serial));

    // Signature algorithm: ecdsa-with-SHA256
    let ecdsa_with_sha256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    tbs.extend_from_slice(&encode_algorithm_identifier(ecdsa_with_sha256_oid));

    // Issuer: CN=WebRTC
    let issuer = encode_name("WebRTC");
    tbs.extend_from_slice(&issuer);

    // Validity: 1 year from now
    let validity = encode_validity()?;
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
        // len fits in a single byte
    } else if len < 256 {
        out.push(0x81);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
    }
    out.push(len as u8);
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

fn encode_validity() -> Result<Vec<u8>, CryptoError> {
    // Use GeneralizedTime for dates
    // Not before: now
    // Not after: 1 year from now

    // For simplicity, use fixed dates that are valid
    // Format: YYYYMMDDHHMMSSZ
    let not_before = b"20240101000000Z";
    let not_after = b"20251231235959Z";

    let nb = encode_tag(0x18, not_before); // GeneralizedTime
    let na = encode_tag(0x18, not_after);

    Ok(encode_sequence(&[nb, na].concat()))
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

fn sign_with_ecdsa_sha256(data: &[u8], private_key: &SecKey) -> Result<Vec<u8>, CryptoError> {
    // Sign using ECDSA with SHA-256 directly with the generated key
    let signature = private_key
        .create_signature(
            security_framework::key::Algorithm::ECDSASignatureMessageX962SHA256,
            data,
        )
        .map_err(|e| CryptoError::Other(format!("Failed to sign: {e}")))?;

    Ok(signature)
}

fn wrap_ec_private_key_pkcs8(
    apple_private_key: &[u8],
    public_key_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Apple exports private key as: 04 || X (32 bytes) || Y (32 bytes) || D (32 bytes) = 97 bytes for P-256
    // Apple exports public key as: 04 || X (32 bytes) || Y (32 bytes) = 65 bytes for P-256
    // We need just the D (private scalar) for SEC1 format

    // PKCS#8 PrivateKeyInfo structure:
    // PrivateKeyInfo ::= SEQUENCE {
    //   version Version,
    //   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
    //   privateKey PrivateKey,
    //   attributes [0] IMPLICIT Attributes OPTIONAL
    // }

    if apple_private_key.len() != 97 {
        return Err(CryptoError::Other(format!(
            "Unexpected Apple private key length: {} (expected 97)",
            apple_private_key.len()
        )));
    }

    // Extract D (private scalar) from Apple format - last 32 bytes
    let private_scalar = &apple_private_key[65..97];

    // Version: 0
    let version = encode_integer(&[0]);

    // Algorithm: ecPublicKey with prime256v1
    let ec_public_key_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let prime256v1_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let algorithm =
        encode_sequence(&[encode_oid(ec_public_key_oid), encode_oid(prime256v1_oid)].concat());

    // PrivateKey: SEC1 ECPrivateKey wrapped in OCTET STRING
    let ec_private_key = encode_ec_private_key(private_scalar, public_key_bytes)?;
    let private_key = encode_tag(0x04, &ec_private_key); // OCTET STRING

    Ok(encode_sequence(&[version, algorithm, private_key].concat()))
}

fn encode_ec_private_key(
    private_scalar: &[u8],
    public_key_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // ECPrivateKey ::= SEQUENCE {
    //   version INTEGER { ecPrivkeyVer1(1) },
    //   privateKey OCTET STRING,
    //   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    //   publicKey [1] BIT STRING OPTIONAL
    // }

    let version = encode_integer(&[1]);
    let private_key = encode_tag(0x04, private_scalar); // OCTET STRING

    // Parameters: prime256v1 OID
    let prime256v1_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let params = encode_explicit_tag(0, &encode_oid(prime256v1_oid));

    // Public key as [1] BIT STRING
    let public_key_bits = encode_bit_string(public_key_bytes);
    let public_key = encode_explicit_tag(1, &public_key_bits);

    Ok(encode_sequence(
        &[version, private_key, params, public_key].concat(),
    ))
}

// DTLS Provider Implementation

use dimpl::{Config, Dtls, DtlsCertificate};

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
                )))
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
