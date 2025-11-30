//! Cipher suite implementations using Apple CommonCrypto.

use dimpl::buffer::{Buf, TmpBuf};
use dimpl::crypto::SupportedCipherSuite;
use dimpl::crypto::{Aad, Cipher, CipherSuite, HashAlgorithm, Nonce};

use crate::ffi::ccNoPadding;
use crate::ffi::kCCAlgorithmAES;
use crate::ffi::kCCDecrypt;
use crate::ffi::kCCEncrypt;
use crate::ffi::kCCModeGCM;
use crate::ffi::kCCSuccess;
use crate::ffi::CCCryptorCreateWithMode;
use crate::ffi::CCCryptorGCMAddAAD;
use crate::ffi::CCCryptorGCMAddIV;
use crate::ffi::CCCryptorGCMDecrypt;
use crate::ffi::CCCryptorGCMEncrypt;
use crate::ffi::CCCryptorGCMFinal;
use crate::ffi::CCCryptorRef;
use crate::ffi::CryptorGuard;
use crate::ffi::GCM_TAG_LEN;

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
        let mut cryptor: CCCryptorRef = std::ptr::null_mut();
        let status = unsafe {
            CCCryptorCreateWithMode(
                kCCEncrypt,
                kCCModeGCM,
                kCCAlgorithmAES,
                ccNoPadding,
                std::ptr::null(),
                self.key.as_ptr() as *const _,
                self.key.len(),
                std::ptr::null(),
                0,
                0,
                0,
                &mut cryptor,
            )
        };
        if status != kCCSuccess {
            return Err(format!("CCCryptorCreateWithMode failed: {status}"));
        }
        let _guard = CryptorGuard(cryptor);

        unsafe {
            let status = CCCryptorGCMAddIV(cryptor, nonce.as_ptr() as *const _, nonce.len());
            if status != kCCSuccess {
                return Err(format!("AddIV failed: {status}"));
            }

            let status = CCCryptorGCMAddAAD(cryptor, aad.as_ptr() as *const _, aad.len());
            if status != kCCSuccess {
                return Err(format!("AddAAD failed: {status}"));
            }

            // Encrypt in-place
            let pt_len = plaintext.len();
            let status = CCCryptorGCMEncrypt(
                cryptor,
                plaintext.as_ptr() as *const _,
                pt_len,
                plaintext.as_mut_ptr() as *mut _,
            );
            if status != kCCSuccess {
                return Err(format!("Encrypt failed: {status}"));
            }

            // Get the tag
            let mut tag = [0u8; GCM_TAG_LEN];
            let mut tag_len = GCM_TAG_LEN;
            let status = CCCryptorGCMFinal(cryptor, tag.as_mut_ptr() as *mut _, &mut tag_len);
            if status != kCCSuccess {
                return Err(format!("Final failed: {status}"));
            }

            // Append tag to ciphertext
            plaintext.extend_from_slice(&tag[..tag_len]);
        }

        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        if ciphertext.len() < GCM_TAG_LEN {
            return Err(format!("Ciphertext too short: {}", ciphertext.len()));
        }

        let ct_len = ciphertext.len() - GCM_TAG_LEN;
        let ct_slice = ciphertext.as_ref();
        let expected_tag = ct_slice[ct_len..].to_vec();

        let mut cryptor: CCCryptorRef = std::ptr::null_mut();
        let status = unsafe {
            CCCryptorCreateWithMode(
                kCCDecrypt,
                kCCModeGCM,
                kCCAlgorithmAES,
                ccNoPadding,
                std::ptr::null(),
                self.key.as_ptr() as *const _,
                self.key.len(),
                std::ptr::null(),
                0,
                0,
                0,
                &mut cryptor,
            )
        };
        if status != kCCSuccess {
            return Err(format!("CCCryptorCreateWithMode failed: {status}"));
        }
        let _guard = CryptorGuard(cryptor);

        unsafe {
            let status = CCCryptorGCMAddIV(cryptor, nonce.as_ptr() as *const _, nonce.len());
            if status != kCCSuccess {
                return Err(format!("AddIV failed: {status}"));
            }

            let status = CCCryptorGCMAddAAD(cryptor, aad.as_ptr() as *const _, aad.len());
            if status != kCCSuccess {
                return Err(format!("AddAAD failed: {status}"));
            }

            // Decrypt in-place (only the ciphertext portion, not the tag)
            let ct_buf = ciphertext.as_mut();
            let status = CCCryptorGCMDecrypt(
                cryptor,
                ct_buf.as_ptr() as *const _,
                ct_len,
                ct_buf.as_mut_ptr() as *mut _,
            );
            if status != kCCSuccess {
                return Err(format!("Decrypt failed: {status}"));
            }

            // Get computed tag and verify
            let mut computed_tag = [0u8; GCM_TAG_LEN];
            let mut tag_len = GCM_TAG_LEN;
            let status =
                CCCryptorGCMFinal(cryptor, computed_tag.as_mut_ptr() as *mut _, &mut tag_len);
            if status != kCCSuccess {
                return Err(format!("Final failed: {status}"));
            }

            // Constant-time comparison
            use subtle::ConstantTimeEq;
            if !bool::from(computed_tag[..tag_len].ct_eq(&expected_tag)) {
                return Err("Tag mismatch".to_string());
            }

            // Truncate to remove the tag from output
            ciphertext.truncate(ct_len);
        }

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
