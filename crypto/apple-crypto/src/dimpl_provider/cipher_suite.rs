//! Cipher suite implementations using Apple CryptoKit.

use dimpl::crypto::SupportedDtls12CipherSuite;
use dimpl::crypto::SupportedDtls13CipherSuite;
use dimpl::crypto::{Aad, Cipher, Dtls12CipherSuite, HashAlgorithm, Nonce};
use dimpl::crypto::{Buf, Dtls13CipherSuite, TmpBuf};
use dimpl::{CryptoError, CryptoOperation};

const AES_GCM_TAG_LEN: usize = 16;

/// AES-GCM cipher implementation using CryptoKit.
struct AesGcm {
    key: crate::cryptokit::AesGcm,
}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcm").finish_non_exhaustive()
    }
}

impl AesGcm {
    fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(CryptoError::InvalidAesGcmKeySize {
                actual: key.len().min(u16::MAX as usize) as u16,
            });
        }
        Ok(Self {
            key: crate::cryptokit::AesGcm::new(key)
                .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Encrypt))?,
        })
    }
}

impl Cipher for AesGcm {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), CryptoError> {
        let original_len = plaintext.len();
        plaintext.resize(original_len + AES_GCM_TAG_LEN, 0);
        if self.key.encrypt_in_place(&nonce, &aad, plaintext).is_err() {
            plaintext.resize(original_len, 0);
            return Err(CryptoError::OperationFailed(CryptoOperation::Encrypt));
        }
        Ok(())
    }

    fn decrypt(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        if ciphertext.len() < AES_GCM_TAG_LEN {
            return Err(CryptoError::CiphertextTooShort {
                minimum: AES_GCM_TAG_LEN as u8,
                actual: ciphertext.len().min(u8::MAX as usize) as u8,
            });
        }
        let output_size = self
            .key
            .decrypt_in_place(&nonce, &aad, ciphertext.as_mut())
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Decrypt))?;
        ciphertext.truncate(output_size);
        Ok(())
    }
}

/// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite.
#[derive(Debug)]
struct Aes128GcmSha256;

impl SupportedDtls12CipherSuite for Aes128GcmSha256 {
    fn suite(&self) -> Dtls12CipherSuite {
        Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 16, 4)
    }

    fn explicit_nonce_len(&self) -> usize {
        8
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

/// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite.
#[derive(Debug)]
struct Aes256GcmSha384;

impl SupportedDtls12CipherSuite for Aes256GcmSha384 {
    fn suite(&self) -> Dtls12CipherSuite {
        Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 32, 4)
    }

    fn explicit_nonce_len(&self) -> usize {
        8
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

static AES_128_GCM_SHA256: Aes128GcmSha256 = Aes128GcmSha256;
static AES_256_GCM_SHA384: Aes256GcmSha384 = Aes256GcmSha384;

pub(super) static ALL_CIPHER_SUITES: &[&dyn SupportedDtls12CipherSuite] =
    &[&AES_128_GCM_SHA256, &AES_256_GCM_SHA384];

/// TLS_AES_128_GCM_SHA256 cipher suite (TLS 1.3 / DTLS 1.3).
#[derive(Debug)]
struct Tls13Aes128GcmSha256;

impl SupportedDtls13CipherSuite for Tls13Aes128GcmSha256 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::AES_128_GCM_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_len(&self) -> usize {
        16 // AES-128
    }

    fn iv_len(&self) -> usize {
        12 // GCM IV
    }

    fn tag_len(&self) -> usize {
        16 // GCM tag
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Ok(Box::new(AesGcm::new(key)?))
    }

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        aes_ecb_encrypt(sn_key, sample)
    }
}

/// TLS_AES_256_GCM_SHA384 cipher suite (TLS 1.3 / DTLS 1.3).
#[derive(Debug)]
struct Tls13Aes256GcmSha384;

impl SupportedDtls13CipherSuite for Tls13Aes256GcmSha384 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::AES_256_GCM_SHA384
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn key_len(&self) -> usize {
        32 // AES-256
    }

    fn iv_len(&self) -> usize {
        12 // GCM IV
    }

    fn tag_len(&self) -> usize {
        16 // GCM tag
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        Ok(Box::new(AesGcm::new(key)?))
    }

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        aes_ecb_encrypt(sn_key, sample)
    }
}

/// Static instances of supported DTLS 1.3 cipher suites.
static TLS13_AES_128_GCM_SHA256: Tls13Aes128GcmSha256 = Tls13Aes128GcmSha256;
static TLS13_AES_256_GCM_SHA384: Tls13Aes256GcmSha384 = Tls13Aes256GcmSha384;

/// All supported DTLS 1.3 cipher suites.
pub(super) static ALL_DTLS13_CIPHER_SUITES: &[&dyn SupportedDtls13CipherSuite] =
    &[&TLS13_AES_128_GCM_SHA256, &TLS13_AES_256_GCM_SHA384];

/// AES-ECB single block encryption for record number protection.
fn aes_ecb_encrypt(key: &[u8], input: &[u8; 16]) -> [u8; 16] {
    let mut output = [0u8; 16];
    crate::common_crypto::aes_ecb_round(key, input, &mut output)
        .expect("AES-ECB encryption failed");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aad() -> Aad {
        let mut aad = Aad(Default::default());
        aad.0.try_extend_from_slice(b"aad").unwrap();
        aad
    }

    #[test]
    fn dtls_cipher_reuses_buffer_storage() {
        for key in [&[0; 16][..], &[0; 32][..]] {
            let mut cipher = AesGcm::new(key).unwrap();
            for size in [0, 1, 16, 1023, 1024, 1500, 4096] {
                let mut buffer = Buf::new();
                buffer.resize(size + AES_GCM_TAG_LEN, 0xab);
                buffer.resize(size, 0);
                let pointer = buffer.as_ptr();
                cipher.encrypt(&mut buffer, aad(), Nonce([0; 12])).unwrap();
                assert_eq!(buffer.len(), size + AES_GCM_TAG_LEN);
                assert_eq!(buffer.as_ptr(), pointer);

                let mut tmp = TmpBuf::new(&mut buffer);
                cipher.decrypt(&mut tmp, aad(), Nonce([0; 12])).unwrap();
                assert_eq!(tmp.len(), size);
                assert_eq!(tmp.as_ref(), &vec![0xab; size]);
                assert_eq!(tmp.as_ref().as_ptr(), pointer);
            }
        }
    }

    #[test]
    fn dtls_decrypt_failure_preserves_ciphertext_and_length() {
        let mut cipher = AesGcm::new(&[0; 16]).unwrap();
        let mut buffer = Buf::new();
        buffer.extend_from_slice(b"hello");
        cipher.encrypt(&mut buffer, aad(), Nonce([0; 12])).unwrap();
        buffer[0] ^= 1;
        let expected = buffer.to_vec();
        let mut tmp = TmpBuf::new(&mut buffer);
        assert!(cipher.decrypt(&mut tmp, aad(), Nonce([0; 12])).is_err());
        assert_eq!(tmp.len(), expected.len());
        assert_eq!(tmp.as_ref(), expected);

        let mut short = [0xa5; 15];
        let mut tmp = TmpBuf::new(&mut short);
        assert!(matches!(
            cipher.decrypt(&mut tmp, aad(), Nonce([0; 12])),
            Err(CryptoError::CiphertextTooShort { .. })
        ));
        assert_eq!(tmp.len(), 15);
        assert_eq!(tmp.as_ref(), &[0xa5; 15]);
    }
}
