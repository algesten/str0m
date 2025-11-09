use super::srtp::SrtpCryptoImpl;
use super::srtp::{aead_aes_128_gcm, aead_aes_256_gcm, aes_128_cm_sha1_80};
use super::CryptoError;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};
use aws_lc_rs::cipher::{EncryptionContext, StreamingEncryptingKey, UnboundCipherKey};
use aws_lc_rs::cipher::{AES_128, AES_256};

use std::io;

const AES_BLOCK_LEN: usize = 16;

pub struct AwsLcImpl;

impl SrtpCryptoImpl for AwsLcImpl {
    type Aes128CmSha1_80 = AwsLcAes128CmSha1_80;
    type AeadAes128Gcm = AwsLcAeadAes128Gcm;
    type AeadAes256Gcm = AwsLcAeadAes256Gcm;

    fn new_aead_aes_128_gcm(
        &self,
        key: super::aead_aes_128_gcm::AeadKey,
        encrypt: bool,
    ) -> Self::AeadAes128Gcm {
        <Self::AeadAes128Gcm as aead_aes_128_gcm::CipherCtx>::new(key, encrypt)
    }

    fn new_aead_aes_256_gcm(
        &self,
        key: super::aead_aes_256_gcm::AeadKey,
        encrypt: bool,
    ) -> Self::AeadAes256Gcm {
        <Self::AeadAes256Gcm as aead_aes_256_gcm::CipherCtx>::new(key, encrypt)
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), 16, "AES-128 ECB expects one 16-byte block");

        let unbound = UnboundCipherKey::new(&AES_128, key).expect("valid AES-128 key");
        let mut encrypting_key =
            StreamingEncryptingKey::ecb_pkcs7(unbound).expect("valid ECB encrypting key");

        // ECB with PKCS7 on 16-byte block adds 16-byte padding = 32 bytes total output
        let b = encrypting_key
            .update(input, output)
            .expect("encryption success");

        let len = b.written().len();

        encrypting_key
            .finish(&mut output[len..])
            .expect("encryption success");
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), 16, "AES-256 ECB expects one 16-byte block");

        let unbound = UnboundCipherKey::new(&AES_256, key).expect("valid AES-256 key");
        let mut encrypting_key =
            StreamingEncryptingKey::ecb_pkcs7(unbound).expect("valid ECB encrypting key");

        // ECB with PKCS7 on 16-byte block adds 16-byte padding = 32 bytes total output
        let b = encrypting_key
            .update(input, output)
            .expect("encryption success");

        let len = b.written().len();

        encrypting_key
            .finish(&mut output[len..])
            .expect("encryption success");
    }
}

pub struct AwsLcAes128CmSha1_80 {
    key: [u8; aes_128_cm_sha1_80::KEY_LEN],
}

pub struct AwsLcAeadAes128Gcm {
    key: LessSafeKey,
}

pub struct AwsLcAeadAes256Gcm {
    key: LessSafeKey,
}

impl aes_128_cm_sha1_80::CipherCtx for AwsLcAes128CmSha1_80 {
    fn new(key: aes_128_cm_sha1_80::AesKey, _encrypt: bool) -> Self
    where
        Self: Sized,
    {
        Self { key }
    }

    fn encrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let unbound = UnboundCipherKey::new(&AES_128, &self.key).expect("valid AES-128 key");

        // Create encryption context with the IV
        let context = EncryptionContext::Iv128((*iv).into());

        let mut encrypting_key =
            StreamingEncryptingKey::less_safe_ctr(unbound, context).expect("CTR init");

        // aws-lc-rs requires output buffer to be input.len() + block_len - 1
        // Caller ensures output buffer is large enough
        let b = encrypting_key
            .update(input, output)
            .map_err(|_| CryptoError::Io(io::Error::other("CTR update")))?;

        let written_len = b.written().len();
        assert_eq!(
            written_len,
            input.len(),
            "CTR mode should produce exactly input.len() bytes"
        );

        // CTR mode doesn't add padding, so finish() should not write any additional bytes
        let mut finish_buf = [0u8; AES_BLOCK_LEN];
        let (_context, finish_result) = encrypting_key
            .finish(&mut finish_buf)
            .map_err(|_| CryptoError::Io(io::Error::other("CTR finish")))?;

        assert_eq!(
            finish_result.written().len(),
            0,
            "CTR finish should not write bytes"
        );

        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        // CTR mode decryption is identical to encryption
        self.encrypt(iv, input, output)
    }
}

impl aead_aes_128_gcm::CipherCtx for AwsLcAeadAes128Gcm {
    fn new(key: aead_aes_128_gcm::AeadKey, _encrypt: bool) -> Self
    where
        Self: Sized,
    {
        let unbound_key = UnboundKey::new(&AES_128_GCM, &key).expect("valid AES-128-GCM key size");
        let less_safe_key = LessSafeKey::new(unbound_key);
        Self { key: less_safe_key }
    }

    fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let nonce = Nonce::try_assume_unique_for_key(iv)
            .map_err(|_| CryptoError::Io(io::Error::other("invalid nonce")))?;

        let ct_len = input.len();
        output[..ct_len].copy_from_slice(input);

        let aad = Aad::from(aad);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, &mut output[..ct_len])
            .map_err(|_| CryptoError::Io(io::Error::other("aead encrypt")))?;

        output[ct_len..ct_len + aead_aes_128_gcm::TAG_LEN].copy_from_slice(tag.as_ref());
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let nonce = Nonce::try_assume_unique_for_key(iv)
            .map_err(|_| CryptoError::Io(io::Error::other("invalid nonce")))?;

        // Combine AADs
        let mut aad_combined_len = 0usize;
        for a in aads {
            aad_combined_len += a.len();
        }
        let mut aad_buf = Vec::with_capacity(aad_combined_len);
        for a in aads {
            aad_buf.extend_from_slice(a);
        }
        let aad = Aad::from(aad_buf.as_slice());

        // aws-lc-rs's open_in_place requires the tag to be at the end of the buffer
        const MAX_STACK_BUF: usize = 2048;

        if input.len() <= MAX_STACK_BUF {
            // Use stack allocation for typical packet sizes
            let mut stack_buf = [0u8; MAX_STACK_BUF];
            stack_buf[..input.len()].copy_from_slice(input);
            let plaintext = self
                .key
                .open_in_place(nonce, aad, &mut stack_buf[..input.len()])
                .map_err(|_| CryptoError::Io(io::Error::other("aead decrypt")))?;
            output[..plaintext.len()].copy_from_slice(plaintext);
            Ok(plaintext.len())
        } else {
            // Large packet - use heap allocation
            tracing::debug!(
                "AES-128-GCM decrypt allocating heap buffer for large packet: input.len()={}",
                input.len()
            );
            let mut in_out = input.to_vec();
            let plaintext = self
                .key
                .open_in_place(nonce, aad, &mut in_out)
                .map_err(|_| CryptoError::Io(io::Error::other("aead decrypt")))?;
            output[..plaintext.len()].copy_from_slice(plaintext);
            Ok(plaintext.len())
        }
    }
}

impl aead_aes_256_gcm::CipherCtx for AwsLcAeadAes256Gcm {
    fn new(key: aead_aes_256_gcm::AeadKey, _encrypt: bool) -> Self
    where
        Self: Sized,
    {
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key).expect("valid AES-256-GCM key size");
        let less_safe_key = LessSafeKey::new(unbound_key);
        Self { key: less_safe_key }
    }

    fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_256_gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let nonce = Nonce::try_assume_unique_for_key(iv)
            .map_err(|_| CryptoError::Io(io::Error::other("invalid nonce")))?;

        let ct_len = input.len();
        output[..ct_len].copy_from_slice(input);

        let aad = Aad::from(aad);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, &mut output[..ct_len])
            .map_err(|_| CryptoError::Io(io::Error::other("aead encrypt")))?;

        output[ct_len..ct_len + aead_aes_256_gcm::TAG_LEN].copy_from_slice(tag.as_ref());
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_256_gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let nonce = Nonce::try_assume_unique_for_key(iv)
            .map_err(|_| CryptoError::Io(io::Error::other("invalid nonce")))?;

        // Combine AADs
        let mut aad_combined_len = 0usize;
        for a in aads {
            aad_combined_len += a.len();
        }
        let mut aad_buf = Vec::with_capacity(aad_combined_len);
        for a in aads {
            aad_buf.extend_from_slice(a);
        }
        let aad = Aad::from(aad_buf.as_slice());

        // aws-lc-rs's open_in_place requires the tag to be at the end of the buffer
        const MAX_STACK_BUF: usize = 2048;

        if input.len() <= MAX_STACK_BUF {
            // Use stack allocation for typical packet sizes
            let mut stack_buf = [0u8; MAX_STACK_BUF];
            stack_buf[..input.len()].copy_from_slice(input);
            let plaintext = self
                .key
                .open_in_place(nonce, aad, &mut stack_buf[..input.len()])
                .map_err(|_| CryptoError::Io(io::Error::other("aead decrypt")))?;
            output[..plaintext.len()].copy_from_slice(plaintext);
            Ok(plaintext.len())
        } else {
            // Large packet - use heap allocation
            tracing::debug!(
                "AES-256-GCM decrypt allocating heap buffer for large packet: input.len()={}",
                input.len()
            );
            let mut in_out = input.to_vec();
            let plaintext = self
                .key
                .open_in_place(nonce, aad, &mut in_out)
                .map_err(|_| CryptoError::Io(io::Error::other("aead decrypt")))?;
            output[..plaintext.len()].copy_from_slice(plaintext);
            Ok(plaintext.len())
        }
    }
}
