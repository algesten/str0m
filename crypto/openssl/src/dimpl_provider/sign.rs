//! Signing and key loading implementations using OpenSSL.

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, KeyProvider};
use dimpl::crypto::{SignatureAlgorithm, SignatureVerifier, SigningKey as SigningKeyTrait};
use dimpl::{CryptoError, CryptoOperation};

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
    fn sign(
        &mut self,
        data: &[u8],
        hash_alg: HashAlgorithm,
        out: &mut Buf,
    ) -> Result<(), CryptoError> {
        let key_hash = self.hash_algorithm();
        if hash_alg != key_hash {
            return Err(CryptoError::SigningKeyHashMismatch {
                key_hash,
                requested: hash_alg,
            });
        }

        let md = match self.curve {
            EcCurve::P256 => MessageDigest::sha256(),
            EcCurve::P384 => MessageDigest::sha384(),
        };

        let mut signer = openssl::sign::Signer::new(md, &self.pkey)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Sign))?;
        signer
            .update(data)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Sign))?;
        let signature = signer
            .sign_to_vec()
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Sign))?;

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

    fn supported_hash_algorithms(&self) -> &[HashAlgorithm] {
        // openssl ECDSA key is bound to the curve's default hash here;
        // only one is supported.
        match self.curve {
            EcCurve::P256 => &[HashAlgorithm::SHA256],
            EcCurve::P384 => &[HashAlgorithm::SHA384],
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
    ) -> Result<Box<dyn SigningKeyTrait>, CryptoError> {
        let ec_key = pkey.ec_key().map_err(|_| CryptoError::InvalidPrivateKey)?;
        let nid = ec_key
            .group()
            .curve_name()
            .ok_or(CryptoError::MissingEcCurveParameter)?;

        let curve = match nid {
            Nid::X9_62_PRIME256V1 => EcCurve::P256,
            Nid::SECP384R1 => EcCurve::P384,
            _ => return Err(CryptoError::UnsupportedEcCurve),
        };

        Ok(Box::new(EcdsaSigningKey { pkey, curve }))
    }
}

impl KeyProvider for OsslKeyProvider {
    fn load_private_key(&self, key_der: &[u8]) -> Result<Box<dyn SigningKeyTrait>, CryptoError> {
        // Try PEM format first using OpenSSL's native parser
        if key_der.starts_with(b"-----BEGIN") {
            let pkey =
                PKey::private_key_from_pem(key_der).map_err(|_| CryptoError::InvalidPrivateKey)?;
            return self.pkey_to_signing_key(pkey);
        }

        // Try PKCS#8 format first, then raw EC key
        let pkey = PKey::private_key_from_der(key_der)
            .or_else(|_| {
                // Try as SEC1 EC private key
                let ec_key = EcKey::private_key_from_der(key_der)
                    .map_err(|_| CryptoError::InvalidPrivateKey)?;
                PKey::from_ec_key(ec_key).map_err(|_| CryptoError::InvalidPrivateKey)
            })
            .map_err(|_| CryptoError::InvalidPrivateKey)?;

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
    ) -> Result<(), CryptoError> {
        if sig_alg != SignatureAlgorithm::ECDSA {
            return Err(CryptoError::UnsupportedSignatureAlgorithm(sig_alg));
        }

        let md = match hash_alg {
            HashAlgorithm::SHA256 => MessageDigest::sha256(),
            HashAlgorithm::SHA384 => MessageDigest::sha384(),
            _ => {
                return Err(CryptoError::UnsupportedSignaturePair {
                    signature: sig_alg,
                    hash: hash_alg,
                });
            }
        };

        // Use OpenSSL's native X.509 parser to extract the public key directly.
        // This avoids fragile key-length-based curve detection and manual SPKI parsing.
        let cert = openssl::x509::X509::from_der(cert_der)
            .map_err(|_| CryptoError::CertificateParseFailed)?;
        let pkey = cert
            .public_key()
            .map_err(|_| CryptoError::InvalidSubjectPublicKey)?;
        let group = match pkey
            .ec_key()
            .map_err(|_| CryptoError::InvalidSubjectPublicKey)?
            .group()
            .curve_name()
            .ok_or(CryptoError::MissingEcCurveParameter)?
        {
            Nid::X9_62_PRIME256V1 => dimpl::NamedGroup::Secp256r1,
            Nid::SECP384R1 => dimpl::NamedGroup::Secp384r1,
            _ => return Err(CryptoError::UnsupportedEcCurve),
        };

        // Verify the signature
        let mut verifier = openssl::sign::Verifier::new(md, &pkey)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::VerifySignature))?;
        verifier
            .update(data)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::VerifySignature))?;
        let valid = verifier
            .verify(signature)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::VerifySignature))?;

        if valid {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed {
                signature: sig_alg,
                hash: hash_alg,
                group,
            })
        }
    }
}

/// Static instance of the key provider.
pub(super) static KEY_PROVIDER: OsslKeyProvider = OsslKeyProvider;

/// Static instance of the signature verifier.
pub(super) static SIGNATURE_VERIFIER: OsslSignatureVerifier = OsslSignatureVerifier;
