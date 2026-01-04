//! Cipher suite implementations using Apple CommonCrypto.

use dimpl::buffer::{Buf, TmpBuf};
use dimpl::crypto::SupportedCipherSuite;
use dimpl::crypto::{Aad, Cipher, CipherSuite, HashAlgorithm, Nonce};

const GCM_TAG_LEN: usize = 12;
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
        let ciphertext_length = plaintext.len() + GCM_TAG_LEN;
        let mut ciphertext = OutputBuffer::new(ciphertext_length);
        let output_size = apple_cryptokit::symmetric::aes::aes_gcm_encrypt_to_with_aad(
            &self.key,
            &nonce,
            plaintext,
            &aad,
            ciphertext.as_mut_slice(),
        )
        .map_err(|err| format!("{err:?}"))?;
        plaintext.clear();
        plaintext.extend_from_slice(&ciphertext.as_slice()[..output_size]);
        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        let plaintext_length = ciphertext.len() - GCM_TAG_LEN;
        let mut output = OutputBuffer::new(plaintext_length);
        let output_size = apple_cryptokit::symmetric::aes::aes_gcm_decrypt_to_with_aad(
            &self.key,
            &nonce,
            ciphertext.as_ref(),
            &aad,
            output.as_mut_slice(),
        )
        .map_err(|err| format!("{err:?}"))?;
        ciphertext.truncate(output_size);
        ciphertext
            .as_mut()
            .copy_from_slice(&output.as_slice()[0..output_size]);
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

enum OutputBuffer {
    Stack([u8; Self::STACK_BUFFER_SIZE]),
    Heap(Vec<u8>),
}

impl OutputBuffer {
    // How large the buffer stored on the stack is. Buffers larger than this
    // will require allocation via the creation of a Vec.
    const STACK_BUFFER_SIZE: usize = 1024;

    fn new(size: usize) -> Self {
        if size < Self::STACK_BUFFER_SIZE {
            Self::Stack([0u8; Self::STACK_BUFFER_SIZE])
        } else {
            Self::Heap(vec![0; size])
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            OutputBuffer::Stack(buffer) => buffer.as_mut_slice(),
            OutputBuffer::Heap(buffer) => buffer.as_mut_slice(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            OutputBuffer::Stack(buffer) => buffer.as_slice(),
            OutputBuffer::Heap(buffer) => buffer.as_slice(),
        }
    }
}
