//! SRTP provider implementation using Windows CNG.

use str0m_proto::crypto::SupportedAes128CmSha1_80;
use str0m_proto::crypto::{AeadAes128GcmCipher, AeadAes256GcmCipher};
use str0m_proto::crypto::{Aes128CmSha1_80Cipher, CryptoError, SrtpProvider};
use str0m_proto::crypto::{SupportedAeadAes128Gcm, SupportedAeadAes256Gcm};

use crate::sys;

#[derive(Debug)]
pub(super) struct WinCryptoSrtpProvider;

impl SrtpProvider for WinCryptoSrtpProvider {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &WinCryptoAes128CmSha1_80Factory
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &WinCryptoAeadAes128GcmFactory
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &WinCryptoAeadAes256GcmFactory
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        let key = sys::SrtpKey::create_aes_ecb_key(key).expect("AES-128 ECB key");
        let count = sys::srtp_aes_ecb_round(&key, input, output).expect("AES-128 ECB");
        assert_eq!(count, 16 + 16); // block size + padding
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        let key = sys::SrtpKey::create_aes_ecb_key(key).expect("AES-256 ECB key");
        let count = sys::srtp_aes_ecb_round(&key, input, output).expect("AES-256 ECB");
        assert_eq!(count, 16 + 16); // block size + padding
    }
}

// Cipher Factories

#[derive(Debug)]
struct WinCryptoAes128CmSha1_80Factory;

impl SupportedAes128CmSha1_80 for WinCryptoAes128CmSha1_80Factory {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        Box::new(WinCryptoAes128CmSha1_80::new(key))
    }
}

#[derive(Debug)]
struct WinCryptoAeadAes128GcmFactory;

impl SupportedAeadAes128Gcm for WinCryptoAeadAes128GcmFactory {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        Box::new(WinCryptoAeadAes128Gcm::new(key))
    }
}

#[derive(Debug)]
struct WinCryptoAeadAes256GcmFactory;

impl SupportedAeadAes256Gcm for WinCryptoAeadAes256GcmFactory {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        Box::new(WinCryptoAeadAes256Gcm::new(key))
    }
}

// Cipher Implementations

struct WinCryptoAes128CmSha1_80 {
    key: sys::SrtpKey,
}

impl std::fmt::Debug for WinCryptoAes128CmSha1_80 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinCryptoAes128CmSha1_80").finish()
    }
}

impl WinCryptoAes128CmSha1_80 {
    fn new(key: [u8; 16]) -> Self {
        Self {
            key: sys::SrtpKey::create_aes_ctr_key(&key).expect("AES-128-CTR key"),
        }
    }
}

impl Aes128CmSha1_80Cipher for WinCryptoAes128CmSha1_80 {
    fn encrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        sys::srtp_aes_128_cm(&self.key, iv, input, output)
            .map_err(|e| CryptoError::Other(format!("AES-128-CM encrypt: {}", e)))?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        sys::srtp_aes_128_cm(&self.key, iv, input, output)
            .map_err(|e| CryptoError::Other(format!("AES-128-CM decrypt: {}", e)))?;
        Ok(())
    }
}

struct WinCryptoAeadAes128Gcm {
    key: sys::SrtpKey,
}

impl std::fmt::Debug for WinCryptoAeadAes128Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinCryptoAeadAes128Gcm").finish()
    }
}

impl WinCryptoAeadAes128Gcm {
    fn new(key: [u8; 16]) -> Self {
        Self {
            key: sys::SrtpKey::create_aes_gcm_key(&key).expect("AES-128-GCM key"),
        }
    }
}

impl AeadAes128GcmCipher for WinCryptoAeadAes128Gcm {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        // wincrypto appends tag to output (output contains ciphertext + 16-byte tag)
        sys::srtp_aead_aes_gcm_encrypt(&self.key, iv, aad, input, output)
            .map_err(|e| CryptoError::Other(format!("AES-128-GCM encrypt: {}", e)))?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        // wincrypto expects input to contain ciphertext + tag
        let written = sys::srtp_aead_aes_gcm_decrypt(&self.key, iv, aads, input, output)
            .map_err(|e| CryptoError::Other(format!("AES-128-GCM decrypt: {}", e)))?;
        Ok(written)
    }
}

struct WinCryptoAeadAes256Gcm {
    key: sys::SrtpKey,
}

impl std::fmt::Debug for WinCryptoAeadAes256Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinCryptoAeadAes256Gcm").finish()
    }
}

impl WinCryptoAeadAes256Gcm {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key: sys::SrtpKey::create_aes_gcm_key(&key).expect("AES-256-GCM key"),
        }
    }
}

impl AeadAes256GcmCipher for WinCryptoAeadAes256Gcm {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        // wincrypto appends tag to output (output contains ciphertext + 16-byte tag)
        sys::srtp_aead_aes_gcm_encrypt(&self.key, iv, aad, input, output)
            .map_err(|e| CryptoError::Other(format!("AES-256-GCM encrypt: {}", e)))?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        // wincrypto expects input to contain ciphertext + tag
        let written = sys::srtp_aead_aes_gcm_decrypt(&self.key, iv, aads, input, output)
            .map_err(|e| CryptoError::Other(format!("AES-256-GCM decrypt: {}", e)))?;
        Ok(written)
    }
}
