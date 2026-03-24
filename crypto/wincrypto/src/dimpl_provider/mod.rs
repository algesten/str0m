//! Windows CNG cryptographic provider for dimpl.
//!
//! This module implements the dimpl crypto provider traits using
//! Windows CNG (Cryptography Next Generation) APIs.

#![allow(unsafe_code)]

mod cipher_suite;
mod hash;
mod hmac;
mod kx_group;
pub(crate) mod sign;

use dimpl::crypto::{CryptoProvider, SecureRandom};

use crate::WinCryptoError;

/// Get the Windows CNG based crypto provider for dimpl.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: cipher_suite::ALL_CIPHER_SUITES,
        dtls13_cipher_suites: cipher_suite::ALL_DTLS13_CIPHER_SUITES,
        kx_groups: kx_group::ALL_KX_GROUPS,
        signature_verification: &sign::SIGNATURE_VERIFIER,
        key_provider: &sign::KEY_PROVIDER,
        secure_random: &SECURE_RANDOM,
        hash_provider: &hash::HASH_PROVIDER,
        hmac_provider: &hmac::HMAC_PROVIDER,
    }
}

#[derive(Debug)]
struct WinCngSecureRandom;

impl SecureRandom for WinCngSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), String> {
        use windows::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG;
        use windows::Win32::Security::Cryptography::BCryptGenRandom;
        // SAFETY: Microsoft Learn documents `BCryptGenRandom` as filling the
        // caller-provided mutable buffer for the duration of the call; `buf`
        // outlives this block.
        // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
        unsafe {
            WinCryptoError::from_ntstatus(BCryptGenRandom(
                None,
                buf,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            ))
            .map_err(|e| format!("BCryptGenRandom failed: {e}"))?;
        }
        Ok(())
    }
}

static SECURE_RANDOM: WinCngSecureRandom = WinCngSecureRandom;

#[cfg(test)]
mod tests {
    #[test]
    fn validate_dimpl_provider() -> Result<(), String> {
        super::default_provider()
            .validate()
            .map_err(|err| format!("{err:?}"))
    }
}
