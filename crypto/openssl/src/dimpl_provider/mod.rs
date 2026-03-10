//! OpenSSL cryptographic provider for dimpl.
//!
//! This module implements the dimpl crypto provider traits using
//! OpenSSL for cryptographic operations.

mod cipher_suite;
mod hash;
mod hkdf;
mod hmac;
mod kx_group;
mod sign;
mod tls12;

use dimpl::crypto::{CryptoProvider, SecureRandom};

/// Get the OpenSSL based crypto provider for dimpl.
pub(crate) fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: cipher_suite::ALL_CIPHER_SUITES,
        dtls13_cipher_suites: cipher_suite::ALL_DTLS13_CIPHER_SUITES,
        kx_groups: kx_group::ALL_KX_GROUPS,
        signature_verification: &sign::SIGNATURE_VERIFIER,
        key_provider: &sign::KEY_PROVIDER,
        secure_random: &SECURE_RANDOM,
        hash_provider: &hash::HASH_PROVIDER,
        prf_provider: &tls12::PRF_PROVIDER,
        hmac_provider: &hmac::HMAC_PROVIDER,
        hkdf_provider: &hkdf::HKDF_PROVIDER,
    }
}

#[derive(Debug)]
struct OsslSecureRandom;

impl SecureRandom for OsslSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), String> {
        openssl::rand::rand_bytes(buf).map_err(|e| format!("OpenSSL random failed: {e}"))
    }
}

static SECURE_RANDOM: OsslSecureRandom = OsslSecureRandom;

#[cfg(test)]
pub(super) mod test_utils {
    pub fn hex_to_vec(hex: &str) -> Vec<u8> {
        assert!(hex.len() % 2 == 0, "hex string must have even length");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    pub fn to_hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Compute HMAC using OpenSSL. Shared utility for HKDF, PRF, and HMAC providers.
pub(super) fn hmac_openssl(
    md: openssl::hash::MessageDigest,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let pkey = openssl::pkey::PKey::hmac(key).map_err(|e| format!("{e}"))?;
    let mut signer = openssl::sign::Signer::new(md, &pkey).map_err(|e| format!("{e}"))?;
    signer.update(data).map_err(|e| format!("{e}"))?;
    signer.sign_to_vec().map_err(|e| format!("{e}"))
}
