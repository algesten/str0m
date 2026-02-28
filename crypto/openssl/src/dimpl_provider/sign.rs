//! Signing and key loading implementations using OpenSSL.

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, KeyProvider};
use dimpl::crypto::{SignatureAlgorithm, SignatureVerifier, SigningKey as SigningKeyTrait};

use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;

/// ECDSA signing key implementation using OpenSSL.
struct EcdsaSigningKey {
    pkey: PKey<openssl::pkey::Private>,
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
        let md = match self.curve {
            EcCurve::P256 => MessageDigest::sha256(),
            EcCurve::P384 => MessageDigest::sha384(),
        };

        let mut signer =
            openssl::sign::Signer::new(md, &self.pkey).map_err(|e| format!("Signer::new: {e}"))?;
        signer.update(data).map_err(|e| format!("update: {e}"))?;
        let signature = signer
            .sign_to_vec()
            .map_err(|e| format!("sign_to_vec: {e}"))?;

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
pub(super) struct OsslKeyProvider;

impl OsslKeyProvider {
    fn pkey_to_signing_key(
        &self,
        pkey: PKey<openssl::pkey::Private>,
    ) -> Result<Box<dyn SigningKeyTrait>, String> {
        let ec_key = pkey.ec_key().map_err(|e| format!("Not an EC key: {e}"))?;
        let nid = ec_key
            .group()
            .curve_name()
            .ok_or_else(|| "Unknown EC curve".to_string())?;

        let curve = match nid {
            Nid::X9_62_PRIME256V1 => EcCurve::P256,
            Nid::SECP384R1 => EcCurve::P384,
            _ => return Err(format!("Unsupported EC curve: {:?}", nid)),
        };

        Ok(Box::new(EcdsaSigningKey { pkey, curve }))
    }
}

impl KeyProvider for OsslKeyProvider {
    fn load_private_key(&self, key_der: &[u8]) -> Result<Box<dyn SigningKeyTrait>, String> {
        // Try PEM format first using OpenSSL's native parser
        if key_der.starts_with(b"-----BEGIN") {
            let pkey = PKey::private_key_from_pem(key_der)
                .map_err(|e| format!("Failed to parse PEM private key: {e}"))?;
            return self.pkey_to_signing_key(pkey);
        }

        // Try PKCS#8 format first, then raw EC key
        let pkey = PKey::private_key_from_der(key_der)
            .or_else(|_| {
                // Try as SEC1 EC private key
                let ec_key = EcKey::private_key_from_der(key_der)
                    .map_err(|e| format!("Failed to parse EC key: {e}"))?;
                PKey::from_ec_key(ec_key).map_err(|e| format!("PKey from EC: {e}"))
            })
            .map_err(|e| format!("Failed to load private key: {e}"))?;

        self.pkey_to_signing_key(pkey)
    }
}

/// Signature verifier implementation.
#[derive(Debug)]
pub(super) struct OsslSignatureVerifier;

impl SignatureVerifier for OsslSignatureVerifier {
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

        let md = match hash_alg {
            HashAlgorithm::SHA256 => MessageDigest::sha256(),
            HashAlgorithm::SHA384 => MessageDigest::sha384(),
            _ => {
                return Err(format!(
                    "Unsupported hash algorithm for ECDSA: {hash_alg:?}"
                ));
            }
        };

        // Use OpenSSL's native X.509 parser to extract the public key directly.
        // This avoids fragile key-length-based curve detection and manual SPKI parsing.
        let cert = openssl::x509::X509::from_der(cert_der)
            .map_err(|e| format!("Failed to parse certificate: {e}"))?;
        let pkey = cert
            .public_key()
            .map_err(|e| format!("Failed to extract public key: {e}"))?;

        // Verify the signature
        let mut verifier =
            openssl::sign::Verifier::new(md, &pkey).map_err(|e| format!("Verifier::new: {e}"))?;
        verifier.update(data).map_err(|e| format!("update: {e}"))?;
        let valid = verifier
            .verify(signature)
            .map_err(|e| format!("verify: {e}"))?;

        if valid {
            Ok(())
        } else {
            Err("ECDSA signature verification failed".to_string())
        }
    }
}

/// Static instance of the key provider.
pub(super) static KEY_PROVIDER: OsslKeyProvider = OsslKeyProvider;

/// Static instance of the signature verifier.
pub(super) static SIGNATURE_VERIFIER: OsslSignatureVerifier = OsslSignatureVerifier;
