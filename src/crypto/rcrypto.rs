use super::srtp::SrtpCryptoImpl;
use super::srtp::{aead_aes_128_gcm, aead_aes_256_gcm, aes_128_cm_sha1_80};
use super::CryptoError;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::BlockEncrypt;
use aes::Aes128;
use aes::Aes256;
use aes_gcm::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use ctr::cipher::{KeyIvInit as CtrKeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use std::io;

pub struct RustCryptoImpl;

impl SrtpCryptoImpl for RustCryptoImpl {
    type Aes128CmSha1_80 = RustCryptoAes128CmSha1_80;
    type AeadAes128Gcm = RustCryptoAeadAes128Gcm;
    type AeadAes256Gcm = RustCryptoAeadAes256Gcm;

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
        debug_assert_eq!(input.len(), 16, "AES-128 ECB expects one 16-byte block");
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(&input[..16]);
        cipher.encrypt_block(&mut block);
        output[..16].copy_from_slice(&block);
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        debug_assert_eq!(input.len(), 16, "AES-256 ECB expects one 16-byte block");
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(&input[..16]);
        cipher.encrypt_block(&mut block);
        output[..16].copy_from_slice(&block);
    }
}

pub struct RustCryptoAes128CmSha1_80 {
    key: [u8; aes_128_cm_sha1_80::KEY_LEN],
}

pub struct RustCryptoAeadAes128Gcm {
    cipher: Aes128Gcm,
}

pub struct RustCryptoAeadAes256Gcm {
    cipher: Aes256Gcm,
}

impl aes_128_cm_sha1_80::CipherCtx for RustCryptoAes128CmSha1_80 {
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
        type AES128CTR = Ctr128BE<Aes128>;
        let mut ctr = AES128CTR::new(
            GenericArray::from_slice(&self.key),
            GenericArray::from_slice(iv),
        );
        output[..input.len()].copy_from_slice(input);
        ctr.apply_keystream(&mut output[..input.len()]);
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

impl aead_aes_128_gcm::CipherCtx for RustCryptoAeadAes128Gcm {
    fn new(key: aead_aes_128_gcm::AeadKey, _encrypt: bool) -> Self
    where
        Self: Sized,
    {
        let cipher = Aes128Gcm::new_from_slice(&key).expect("valid key size");
        Self { cipher }
    }

    fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let nonce = Nonce::from_slice(iv);
        // Copy plaintext into the output buffer, then encrypt in place
        let ct_len = input.len();
        output[..ct_len].copy_from_slice(input);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, aad, &mut output[..ct_len])
            .map_err(|_| CryptoError::Io(io::Error::other("aead encrypt")))?;
        output[ct_len..ct_len + aead_aes_128_gcm::TAG_LEN].copy_from_slice(tag.as_slice());
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let nonce = Nonce::from_slice(iv);
        let (ct, tag_bytes) = input.split_at(input.len() - aead_aes_128_gcm::TAG_LEN);
        output[..ct.len()].copy_from_slice(ct);
        let mut aad_combined_len = 0usize;
        for a in aads {
            aad_combined_len += a.len();
        }
        let mut aad_buf = Vec::with_capacity(aad_combined_len);
        for a in aads {
            aad_buf.extend_from_slice(a);
        }
        let tag = Tag::from_slice(tag_bytes);
        self.cipher
            .decrypt_in_place_detached(nonce, &aad_buf, &mut output[..ct.len()], tag)
            .map_err(|_| CryptoError::Io(io::Error::other("aead decrypt")))?;
        Ok(ct.len())
    }
}

impl aead_aes_256_gcm::CipherCtx for RustCryptoAeadAes256Gcm {
    fn new(key: aead_aes_256_gcm::AeadKey, _encrypt: bool) -> Self
    where
        Self: Sized,
    {
        let cipher = Aes256Gcm::new_from_slice(&key).expect("valid key size");
        Self { cipher }
    }

    fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_256_gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let nonce = Nonce::from_slice(iv);
        let ct_len = input.len();
        output[..ct_len].copy_from_slice(input);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, aad, &mut output[..ct_len])
            .map_err(|_| CryptoError::Io(io::Error::other("aead encrypt")))?;
        output[ct_len..ct_len + aead_aes_256_gcm::TAG_LEN].copy_from_slice(tag.as_slice());
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_256_gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let nonce = Nonce::from_slice(iv);
        let (ct, tag_bytes) = input.split_at(input.len() - aead_aes_256_gcm::TAG_LEN);
        output[..ct.len()].copy_from_slice(ct);
        let mut aad_combined_len = 0usize;
        for a in aads {
            aad_combined_len += a.len();
        }
        let mut aad_buf = Vec::with_capacity(aad_combined_len);
        for a in aads {
            aad_buf.extend_from_slice(a);
        }
        let tag = Tag::from_slice(tag_bytes);
        self.cipher
            .decrypt_in_place_detached(nonce, &aad_buf, &mut output[..ct.len()], tag)
            .map_err(|_| CryptoError::Io(io::Error::other("aead decrypt")))?;
        Ok(ct.len())
    }
}
