//! Signing and key loading implementations for Apple platforms using Security framework.

use std::ffi::c_void;
use std::str;

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::error::CFError;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use der::Decode;
use dimpl::crypto::Buf;
use security_framework::key::{Algorithm, SecKey};
use spki::ObjectIdentifier;
use x509_cert::Certificate as X509Certificate;

use dimpl::crypto::{HashAlgorithm, KeyProvider};
use dimpl::crypto::{SignatureAlgorithm, SignatureVerifier, SigningKey as SigningKeyTrait};

// Security framework FFI bindings
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecAttrKeyType: core_foundation::string::CFStringRef;
    static kSecAttrKeyTypeECSECPrimeRandom: core_foundation::string::CFStringRef;
    static kSecAttrKeyClass: core_foundation::string::CFStringRef;
    static kSecAttrKeyClassPrivate: core_foundation::string::CFStringRef;
    static kSecAttrKeyClassPublic: core_foundation::string::CFStringRef;
    static kSecAttrKeySizeInBits: core_foundation::string::CFStringRef;

    fn SecKeyCreateWithData(
        key_data: *const c_void,
        attributes: *const c_void,
        error: *mut *const c_void,
    ) -> *mut c_void;
}

/// ECDSA signing key implementation using Security framework.
struct EcdsaSigningKey {
    key: SecKey,
    curve: EcCurve,
}

#[derive(Clone, Copy, Debug)]
enum EcCurve {
    P256,
    P384,
}

impl std::fmt::Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.curve {
            EcCurve::P256 => f.debug_tuple("EcdsaSigningKey::P256").finish(),
            EcCurve::P384 => f.debug_tuple("EcdsaSigningKey::P384").finish(),
        }
    }
}

impl SigningKeyTrait for EcdsaSigningKey {
    fn sign(&mut self, data: &[u8], out: &mut Buf) -> Result<(), String> {
        // Sized to the largest hash size we support.
        let mut hash_buffer = [0; apple_cryptokit::hashing::sha384::SHA384_OUTPUT_SIZE];

        // Hash the data first (Security framework needs pre-hashed data for digest algorithms)
        let (hash_length, algorithm) = match self.curve {
            EcCurve::P256 => {
                apple_cryptokit::hashing::sha256_hash_to(data, hash_buffer.as_mut_slice());
                (
                    apple_cryptokit::hashing::sha256::SHA256_OUTPUT_SIZE,
                    Algorithm::ECDSASignatureDigestX962SHA256,
                )
            }
            EcCurve::P384 => {
                apple_cryptokit::hashing::sha384_hash_to(data, hash_buffer.as_mut_slice());
                (
                    apple_cryptokit::hashing::sha384::SHA384_OUTPUT_SIZE,
                    Algorithm::ECDSASignatureDigestX962SHA384,
                )
            }
        };

        // Sign using Security framework
        let signature = self
            .key
            .create_signature(algorithm, &hash_buffer[..hash_length])
            .map_err(|e| format!("Signing failed: {e}"))?;

        out.clear();
        out.extend_from_slice(&signature);
        Ok(())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self.curve {
            EcCurve::P256 => HashAlgorithm::SHA256,
            EcCurve::P384 => HashAlgorithm::SHA384,
        }
    }
}

/// Key provider implementation.
#[derive(Debug)]
pub(super) struct AppleCryptoKeyProvider;

impl KeyProvider for AppleCryptoKeyProvider {
    fn load_private_key(&self, key_der: &[u8]) -> Result<Box<dyn SigningKeyTrait>, String> {
        // Try to check if it's PEM encoded first
        if let Ok(pem_str) = str::from_utf8(key_der) {
            if pem_str.contains("-----BEGIN") {
                if let Ok((_label, doc)) = pkcs8::Document::from_pem(pem_str) {
                    return self.load_private_key(doc.as_bytes());
                }
            }
        }

        // Extract raw key bytes in format Apple expects
        let (curve, apple_key_data) = extract_apple_key_data(key_der)
            .map_err(|e| format!("Failed to extract key data: {e}"))?;

        let key_size = match curve {
            EcCurve::P256 => 256,
            EcCurve::P384 => 384,
        };

        // Create key attributes for EC private key
        let key_data = CFData::from_buffer(&apple_key_data);

        // Build attributes dictionary using CFMutableDictionary
        let attributes = unsafe {
            let mut dict: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();

            let key_type_key = CFString::wrap_under_get_rule(kSecAttrKeyType);
            let key_type_value = CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom);
            dict.set(key_type_key, key_type_value.as_CFType());

            let key_class_key = CFString::wrap_under_get_rule(kSecAttrKeyClass);
            let key_class_value = CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate);
            dict.set(key_class_key, key_class_value.as_CFType());

            let key_size_key = CFString::wrap_under_get_rule(kSecAttrKeySizeInBits);
            let key_size_value = CFNumber::from(key_size);
            dict.set(key_size_key, key_size_value.as_CFType());

            dict
        };

        // Create key from data
        let mut error: core_foundation::error::CFErrorRef = std::ptr::null_mut();
        let key_ref = unsafe {
            SecKeyCreateWithData(
                key_data.as_concrete_TypeRef() as *const _,
                attributes.as_concrete_TypeRef() as *const _,
                &mut error as *mut _ as *mut *const c_void,
            )
        };

        if key_ref.is_null() {
            let error_msg = if !error.is_null() {
                let cf_error = unsafe { CFError::wrap_under_create_rule(error) };
                format!("{cf_error}")
            } else {
                "Unknown error".to_string()
            };
            return Err(format!(
                "SecKeyCreateWithData failed for {:?} key (data len: {}): {}",
                curve,
                apple_key_data.len(),
                error_msg
            ));
        }

        let key = unsafe { SecKey::wrap_under_create_rule(key_ref as *mut _) };

        Ok(Box::new(EcdsaSigningKey { key, curve }))
    }
}

/// Extract raw EC private key bytes for Apple Security framework from PKCS#8 or SEC1 format.
/// Apple's SecKeyCreateWithData for EC private keys expects the raw key data in the format:
/// For private keys: 04 || X || Y || D (uncompressed public point + private scalar)
/// For P-256: 1 + 32 + 32 + 32 = 97 bytes
/// For P-384: 1 + 48 + 48 + 48 = 145 bytes
fn extract_apple_key_data(key_der: &[u8]) -> Result<(EcCurve, Vec<u8>), String> {
    // Try PKCS#8 format first - extract the SEC1 ECPrivateKey from inside
    let sec1_data = pkcs8::PrivateKeyInfo::from_der(key_der)
        .map_or_else(|_| key_der.to_vec(), |info| info.private_key.to_vec());

    // Parse SEC1 ECPrivateKey structure to extract raw bytes
    let ec_key = sec1::EcPrivateKey::try_from(sec1_data.as_slice())
        .map_err(|e| format!("Failed to parse SEC1 ECPrivateKey: {e}"))?;

    let private_key_bytes = ec_key.private_key;
    let private_key_len = private_key_bytes.len();

    // Determine curve from parameters or key length
    let curve = if let Some(params) = &ec_key.parameters {
        match params {
            sec1::EcParameters::NamedCurve(oid) => {
                let p256_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
                let p384_oid = ObjectIdentifier::new_unwrap("1.3.132.0.34");

                if *oid == p256_oid {
                    EcCurve::P256
                } else if *oid == p384_oid {
                    EcCurve::P384
                } else {
                    return Err(format!("Unsupported EC curve OID: {oid}"));
                }
            }
        }
    } else if private_key_len == 32 {
        EcCurve::P256
    } else if private_key_len == 48 {
        EcCurve::P384
    } else {
        return Err(format!(
            "Could not determine EC curve from key length: {private_key_len}"
        ));
    };

    // Apple's SecKeyCreateWithData for EC private keys expects:
    // 04 || X (coord_size bytes) || Y (coord_size bytes) || D (private key, coord_size bytes)
    // This is the uncompressed public point followed by the private scalar
    let public_key_bytes = ec_key
        .public_key
        .as_ref()
        .ok_or_else(|| "EC private key missing public key component".to_string())?;

    let coord_size = match curve {
        EcCurve::P256 => 32,
        EcCurve::P384 => 48,
    };

    // Public key should be uncompressed format: 04 || X || Y
    let expected_pub_len = 1 + 2 * coord_size;
    if public_key_bytes.len() != expected_pub_len {
        return Err(format!(
            "Unexpected public key length: {} (expected {})",
            public_key_bytes.len(),
            expected_pub_len
        ));
    }

    // Build Apple format: 04 || X || Y || D
    // The public key already has the 04 prefix
    let mut apple_key_data = Vec::with_capacity(expected_pub_len + coord_size);
    apple_key_data.extend_from_slice(public_key_bytes.as_ref()); // 04 || X || Y
    apple_key_data.extend_from_slice(private_key_bytes); // D

    Ok((curve, apple_key_data))
}

/// Signature verifier implementation.
#[derive(Debug)]
pub(super) struct AppleCryptoSignatureVerifier;

impl SignatureVerifier for AppleCryptoSignatureVerifier {
    fn verify_signature(
        &self,
        cert_der: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlgorithm,
        sig_alg: SignatureAlgorithm,
    ) -> Result<(), String> {
        if sig_alg != SignatureAlgorithm::ECDSA {
            return Err(format!("Unsupported signature algorithm: {sig_alg:?}"));
        }

        let cert = X509Certificate::from_der(cert_der)
            .map_err(|e| format!("Failed to parse certificate: {e}"))?;
        let spki = &cert.tbs_certificate.subject_public_key_info;

        const OID_EC_PUBLIC_KEY: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

        if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
            return Err(format!(
                "Unsupported public key algorithm: {}",
                spki.algorithm.oid
            ));
        }

        let pubkey_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| "Invalid EC subject_public_key bitstring".to_string())?;

        // Determine key size from public key length or algorithm parameters
        let key_size = if pubkey_bytes.len() == 65 {
            256 // P-256: 1 byte prefix + 32 bytes X + 32 bytes Y
        } else if pubkey_bytes.len() == 97 {
            384 // P-384: 1 byte prefix + 48 bytes X + 48 bytes Y
        } else {
            return Err(format!(
                "Unsupported EC public key size: {} bytes",
                pubkey_bytes.len()
            ));
        };

        // Sized to the largest hash size we support.
        let mut hash_buffer = [0; apple_cryptokit::hashing::sha384::SHA384_OUTPUT_SIZE];

        // Hash the data
        let (hash_length, algorithm) = match hash_alg {
            HashAlgorithm::SHA256 => {
                apple_cryptokit::hashing::sha256_hash_to(data, hash_buffer.as_mut_slice());
                (
                    apple_cryptokit::hashing::sha256::SHA256_OUTPUT_SIZE,
                    Algorithm::ECDSASignatureDigestX962SHA256,
                )
            }
            HashAlgorithm::SHA384 => {
                apple_cryptokit::hashing::sha384_hash_to(data, hash_buffer.as_mut_slice());
                (
                    apple_cryptokit::hashing::sha384::SHA384_OUTPUT_SIZE,
                    Algorithm::ECDSASignatureDigestX962SHA384,
                )
            }
            _ => {
                return Err(format!(
                    "Unsupported hash algorithm for ECDSA: {hash_alg:?}"
                ));
            }
        };

        // Create public key from data
        let key_data = CFData::from_buffer(pubkey_bytes);

        // Build attributes dictionary using CFMutableDictionary
        let attributes = unsafe {
            let mut dict: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();

            let key_type_key = CFString::wrap_under_get_rule(kSecAttrKeyType);
            let key_type_value = CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom);
            dict.set(key_type_key, key_type_value.as_CFType());

            let key_class_key = CFString::wrap_under_get_rule(kSecAttrKeyClass);
            let key_class_value = CFString::wrap_under_get_rule(kSecAttrKeyClassPublic);
            dict.set(key_class_key, key_class_value.as_CFType());

            let key_size_key = CFString::wrap_under_get_rule(kSecAttrKeySizeInBits);
            let key_size_value = CFNumber::from(key_size);
            dict.set(key_size_key, key_size_value.as_CFType());

            dict
        };

        // Create key from data
        let mut error: core_foundation::error::CFErrorRef = std::ptr::null_mut();
        let key_ref = unsafe {
            SecKeyCreateWithData(
                key_data.as_concrete_TypeRef() as *const _,
                attributes.as_concrete_TypeRef() as *const _,
                &mut error as *mut _ as *mut *const c_void,
            )
        };

        if key_ref.is_null() {
            let error_msg = if !error.is_null() {
                let cf_error = unsafe { CFError::wrap_under_create_rule(error) };
                format!("{cf_error}")
            } else {
                "Unknown error".to_string()
            };
            return Err(format!(
                "Failed to create public key for verification: {error_msg}"
            ));
        }

        let public_key = unsafe { SecKey::wrap_under_create_rule(key_ref as *mut _) };

        // Verify the signature using the high-level API
        public_key
            .verify_signature(algorithm, &hash_buffer[..hash_length], signature)
            .map_err(|e| format!("ECDSA signature verification failed: {e}"))?;

        Ok(())
    }
}

/// Static instance of the key provider.
pub(super) static KEY_PROVIDER: AppleCryptoKeyProvider = AppleCryptoKeyProvider;

/// Static instance of the signature verifier.
pub(super) static SIGNATURE_VERIFIER: AppleCryptoSignatureVerifier = AppleCryptoSignatureVerifier;
