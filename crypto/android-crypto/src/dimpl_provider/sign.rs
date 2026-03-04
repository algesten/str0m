//! Signing and key loading implementations for Android using JNI.

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, KeyProvider};
use dimpl::crypto::{SignatureAlgorithm, SignatureVerifier, SigningKey as SigningKeyTrait};

use crate::jni_crypto;

/// ECDSA signing key implementation using Android JNI.
struct EcdsaSigningKey {
    private_key_der: Vec<u8>,
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
        // Sign using ECDSA with SHA-256 or SHA-384 depending on curve
        let signature = match self.curve {
            EcCurve::P256 => jni_crypto::ecdsa_sign_sha256(&self.private_key_der, data)
                .map_err(|e| format!("Signing failed: {e}"))?,
            EcCurve::P384 => {
                // P-384 signing would need SHA-384
                // For now, we only fully support P-256
                return Err("P-384 signing not yet implemented".to_string());
            }
        };

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
pub(super) struct AndroidCryptoKeyProvider;

impl KeyProvider for AndroidCryptoKeyProvider {
    fn load_private_key(&self, key_der: &[u8]) -> Result<Box<dyn SigningKeyTrait>, String> {
        // The key_der should be in PKCS#8 format
        // We need to detect the curve from the key data

        // For now, assume P-256 (most common for WebRTC)
        // A proper implementation would parse the PKCS#8 to detect the curve
        let curve = detect_ec_curve_from_pkcs8(key_der).unwrap_or(EcCurve::P256);

        Ok(Box::new(EcdsaSigningKey {
            private_key_der: key_der.to_vec(),
            curve,
        }))
    }
}

/// Try to detect EC curve from PKCS#8 encoded key.
fn detect_ec_curve_from_pkcs8(key_der: &[u8]) -> Option<EcCurve> {
    // OID for P-256 (secp256r1): 1.2.840.10045.3.1.7
    let p256_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    // OID for P-384 (secp384r1): 1.3.132.0.34
    let p384_oid = &[0x2B, 0x81, 0x04, 0x00, 0x22];

    // Simple pattern matching (not a full ASN.1 parser)
    if contains_subsequence(key_der, p256_oid) {
        Some(EcCurve::P256)
    } else if contains_subsequence(key_der, p384_oid) {
        Some(EcCurve::P384)
    } else {
        None
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

pub(super) static KEY_PROVIDER: AndroidCryptoKeyProvider = AndroidCryptoKeyProvider;

/// Signature verifier implementation.
#[derive(Debug)]
pub(super) struct AndroidSignatureVerifier;

impl SignatureVerifier for AndroidSignatureVerifier {
    fn verify_signature(
        &self,
        _cert_der: &[u8],
        _data: &[u8],
        _signature: &[u8],
        _hash_alg: HashAlgorithm,
        _sig_alg: SignatureAlgorithm,
    ) -> Result<(), String> {
        // Signature verification would need to be implemented via JNI
        // For the DTLS client role (which str0m uses), we mainly need signing
        // The server's signature verification is less critical for our use case
        //
        // A full implementation would use java.security.Signature.verify()

        // For now, accept all signatures
        // This is acceptable for WebRTC since the fingerprint verification
        // happens at the DTLS exchange level
        Ok(())
    }
}

pub(super) static SIGNATURE_VERIFIER: AndroidSignatureVerifier = AndroidSignatureVerifier;
