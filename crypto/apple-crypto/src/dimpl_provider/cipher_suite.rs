//! Cipher suite implementations using Apple CommonCrypto.

use dimpl::buffer::{Buf, TmpBuf};
use dimpl::crypto::SupportedCipherSuite;
use dimpl::crypto::{Aad, Cipher, CipherSuite, HashAlgorithm, Nonce};

/// AES-GCM cipher implementation using CommonCrypto.
struct AesGcm {
    key: Vec<u8>,
}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcm").finish_non_exhaustive()
    }
}

impl AesGcm {
    fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != 16 && key.len() != 32 {
            return Err(format!("Invalid key size for AES-GCM: {}", key.len()));
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl Cipher for AesGcm {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        let output = apple_cryptokit::aes_gcm_encrypt_with_aad(&self.key, &nonce, plaintext, &aad)
            .map_err(|err| format!("{err:?}"))?;
        plaintext.clear();
        plaintext.copy_from_slice(&output);
        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        let output =
            apple_cryptokit::aes_gcm_decrypt_with_aad(&self.key, &nonce, ciphertext.as_ref(), &aad)
                .map_err(|err| format!("{err:?}"))?;
        ciphertext.truncate(0);
        ciphertext.as_mut().copy_from_slice(&output);
        Ok(())
    }
}

/// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite.
#[derive(Debug)]
struct Aes128GcmSha256;

impl SupportedCipherSuite for Aes128GcmSha256 {
    fn suite(&self) -> CipherSuite {
        CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 16, 4)
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

/// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite.
#[derive(Debug)]
struct Aes256GcmSha384;

impl SupportedCipherSuite for Aes256GcmSha384 {
    fn suite(&self) -> CipherSuite {
        CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 32, 4)
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

static AES_128_GCM_SHA256: Aes128GcmSha256 = Aes128GcmSha256;
static AES_256_GCM_SHA384: Aes256GcmSha384 = Aes256GcmSha384;

pub(super) static ALL_CIPHER_SUITES: &[&dyn SupportedCipherSuite] =
    &[&AES_128_GCM_SHA256, &AES_256_GCM_SHA384];
