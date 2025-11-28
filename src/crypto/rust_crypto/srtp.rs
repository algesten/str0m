//! SRTP cipher implementations using RustCrypto.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::crypto::error::CryptoError;
use crate::crypto::provider::{AeadAes128Gcm, AeadAes128GcmCipher};
use crate::crypto::provider::{AeadAes256Gcm, AeadAes256GcmCipher, Aes128CmSha1_80Cipher};
use crate::crypto::provider::{SrtpProvider, SupportedAeadAes128Gcm};
use crate::crypto::provider::{SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};

// Type alias for AES-128 in CTR mode
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

// ============================================================================
// AES-128-CM-SHA1-80 Cipher
// ============================================================================

struct RustCryptoAes128CmSha1_80Cipher {
    key: [u8; 16],
}

impl std::fmt::Debug for RustCryptoAes128CmSha1_80Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoAes128CmSha1_80Cipher").finish()
    }
}

impl Aes128CmSha1_80Cipher for RustCryptoAes128CmSha1_80Cipher {
    fn encrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        // AES-128 Counter Mode (CTR)
        let mut cipher = Aes128Ctr::new(&self.key.into(), iv.into());

        // Copy input to output
        output[..input.len()].copy_from_slice(input);

        // Apply CTR mode encryption (XOR with keystream)
        cipher.apply_keystream(&mut output[..input.len()]);

        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        // AES-CTR is symmetric (same operation for encrypt and decrypt)
        self.encrypt(iv, input, output)
    }
}

// ============================================================================
// AEAD-AES-128-GCM Cipher
// ============================================================================

struct RustCryptoAeadAes128GcmCipher {
    cipher: Aes128Gcm,
}

impl std::fmt::Debug for RustCryptoAeadAes128GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoAeadAes128GcmCipher").finish()
    }
}

impl AeadAes128GcmCipher for RustCryptoAeadAes128GcmCipher {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadAes128Gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        assert!(
            aad.len() >= 12,
            "Associated data length MUST be at least 12 octets"
        );

        let nonce = Nonce::from_slice(iv);
        let payload = Payload { msg: input, aad };

        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::Other(format!("AES-GCM encrypt failed: {:?}", e)))?;

        output[..ciphertext.len()].copy_from_slice(&ciphertext);
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; AeadAes128Gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert!(input.len() >= AeadAes128Gcm::TAG_LEN);

        let nonce = Nonce::from_slice(iv);

        // Concatenate AAD slices if needed
        let aad_vec: Vec<u8>;
        let aad = if aads.len() == 1 {
            aads[0]
        } else {
            aad_vec = aads.concat();
            &aad_vec
        };

        let payload = Payload { msg: input, aad };

        let plaintext = self
            .cipher
            .decrypt(nonce, payload)
            .map_err(|e| CryptoError::Other(format!("AES-GCM decrypt failed: {:?}", e)))?;

        output[..plaintext.len()].copy_from_slice(&plaintext);
        Ok(plaintext.len())
    }
}

// ============================================================================
// AEAD-AES-256-GCM Cipher
// ============================================================================

struct RustCryptoAeadAes256GcmCipher {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for RustCryptoAeadAes256GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoAeadAes256GcmCipher").finish()
    }
}

impl AeadAes256GcmCipher for RustCryptoAeadAes256GcmCipher {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadAes256Gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        assert!(
            aad.len() >= 12,
            "Associated data length MUST be at least 12 octets"
        );

        let nonce = Nonce::from_slice(iv);
        let payload = Payload { msg: input, aad };

        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::Other(format!("AES-GCM encrypt failed: {:?}", e)))?;

        output[..ciphertext.len()].copy_from_slice(&ciphertext);
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; AeadAes256Gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert!(input.len() >= AeadAes256Gcm::TAG_LEN);

        let nonce = Nonce::from_slice(iv);

        // Concatenate AAD slices if needed
        let aad_vec: Vec<u8>;
        let aad = if aads.len() == 1 {
            aads[0]
        } else {
            aad_vec = aads.concat();
            &aad_vec
        };

        let payload = Payload { msg: input, aad };

        let plaintext = self
            .cipher
            .decrypt(nonce, payload)
            .map_err(|e| CryptoError::Other(format!("AES-GCM decrypt failed: {:?}", e)))?;

        output[..plaintext.len()].copy_from_slice(&plaintext);
        Ok(plaintext.len())
    }
}

// ============================================================================
// SRTP Profile Support Implementations
// ============================================================================

struct RustCryptoSupportedAes128CmSha1_80;

impl std::fmt::Debug for RustCryptoSupportedAes128CmSha1_80 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSupportedAes128CmSha1_80")
            .finish()
    }
}

impl SupportedAes128CmSha1_80 for RustCryptoSupportedAes128CmSha1_80 {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        Box::new(RustCryptoAes128CmSha1_80Cipher { key })
    }
}

struct RustCryptoSupportedAeadAes128Gcm;

impl std::fmt::Debug for RustCryptoSupportedAeadAes128Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSupportedAeadAes128Gcm").finish()
    }
}

impl SupportedAeadAes128Gcm for RustCryptoSupportedAeadAes128Gcm {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
        Box::new(RustCryptoAeadAes128GcmCipher { cipher })
    }
}

struct RustCryptoSupportedAeadAes256Gcm;

impl std::fmt::Debug for RustCryptoSupportedAeadAes256Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSupportedAeadAes256Gcm").finish()
    }
}

impl SupportedAeadAes256Gcm for RustCryptoSupportedAeadAes256Gcm {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        Box::new(RustCryptoAeadAes256GcmCipher { cipher })
    }
}

// ============================================================================
// SRTP Provider Implementation
// ============================================================================

pub(super) struct RustCryptoSrtpProvider;

impl std::fmt::Debug for RustCryptoSrtpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSrtpProvider").finish()
    }
}

impl SrtpProvider for RustCryptoSrtpProvider {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &RustCryptoSupportedAes128CmSha1_80
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &RustCryptoSupportedAeadAes128Gcm
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &RustCryptoSupportedAeadAes256Gcm
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        // Use aes crate for ECB mode
        use aes::cipher::{BlockEncrypt, KeyInit};
        use aes::Aes128;

        let cipher = Aes128::new(GenericArray::from_slice(key));

        // Input is 16 bytes, output needs to be 32 bytes (with PKCS7 padding)
        // For a 16-byte input, PKCS7 adds a full block of padding (16 bytes of 0x10)
        assert!(input.len() == 16);
        assert!(output.len() >= 32);

        // First block: encrypt the input
        let mut block1 = *GenericArray::from_slice(&input[0..16]);
        cipher.encrypt_block(&mut block1);
        output[0..16].copy_from_slice(&block1);

        // Second block: PKCS7 padding (16 bytes of 0x10)
        let mut block2 = GenericArray::from([0x10u8; 16]);
        cipher.encrypt_block(&mut block2);
        output[16..32].copy_from_slice(&block2);
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        // Use aes crate for ECB mode
        use aes::cipher::{BlockEncrypt, KeyInit};
        use aes::Aes256;

        let cipher = Aes256::new(GenericArray::from_slice(key));

        // Input is 16 bytes, output needs to be 32 bytes (with PKCS7 padding)
        // For a 16-byte input, PKCS7 adds a full block of padding (16 bytes of 0x10)
        assert!(input.len() == 16);
        assert!(output.len() >= 32);

        // First block: encrypt the input
        let mut block1 = *GenericArray::from_slice(&input[0..16]);
        cipher.encrypt_block(&mut block1);
        output[0..16].copy_from_slice(&block1);

        // Second block: PKCS7 padding (16 bytes of 0x10)
        let mut block2 = GenericArray::from([0x10u8; 16]);
        cipher.encrypt_block(&mut block2);
        output[16..32].copy_from_slice(&block2);
    }
}
