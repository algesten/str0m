use str0m_wincrypto::{
    srtp_aead_aes_128_gcm_decrypt, srtp_aead_aes_128_gcm_encrypt, srtp_aes_128_cm, SrtpKey,
};

use crate::crypto::srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80};
use crate::crypto::CryptoError;

pub(super) fn srtp_aes_128_ecb_round(key: &[u8], input: &[u8], output: &mut [u8]) {
    let key = SrtpKey::new_aes_ecb_key(key).expect("AES key");
    let count = str0m_wincrypto::srtp_aes_128_ecb_round(&key, input, output).expect("AES encrypt");
    assert_eq!(count, 16 + 16); // block size
}

pub(super) struct Aes128CmSha1_80Impl {
    key: SrtpKey,
}

impl Aes128CmSha1_80Impl {
    /// Create a new context for AES-128-CM-SHA1-80 encryption/decryption.
    ///
    /// The encrypt flag is ignored, since the same operation is used for both encryption and
    /// decryption.
    pub(super) fn new(
        key: &aes_128_cm_sha1_80::AesKey,
        _encrypt: bool,
    ) -> Box<dyn aes_128_cm_sha1_80::CipherCtx> {
        Box::new(Self {
            key: SrtpKey::new_aes_ctr_key(key).expect("generate sym key"),
        })
    }
}

impl aes_128_cm_sha1_80::CipherCtx for Aes128CmSha1_80Impl {
    fn encrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> Result<(), CryptoError> {
        srtp_aes_128_cm(&self.key, iv, plain_text, cipher_text)?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        cipher_text: &[u8],
        plain_text: &mut [u8],
    ) -> Result<(), CryptoError> {
        srtp_aes_128_cm(&self.key, iv, cipher_text, plain_text)?;
        Ok(())
    }
}

pub(super) struct AeadAes128GcmImpl {
    key: SrtpKey,
}

impl AeadAes128GcmImpl {
    /// Create a new context for AES-128-GCM encryption/decryption.
    ///
    /// The encrypt flag is ignored, since it is not needed and the same
    /// key can be used for both encryption and decryption.
    pub(super) fn new(
        key: &aead_aes_128_gcm::AeadKey,
        _encrypt: bool,
    ) -> Box<dyn aead_aes_128_gcm::CipherCtx> {
        Box::new(Self {
            key: SrtpKey::new_aes_gcm_key(key).expect("generate sym key"),
        })
    }
}

impl aead_aes_128_gcm::CipherCtx for AeadAes128GcmImpl {
    fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        additional_auth_data: &[u8],
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> Result<(), CryptoError> {
        srtp_aead_aes_128_gcm_encrypt(
            &self.key,
            iv,
            additional_auth_data,
            plain_text,
            cipher_text,
        )?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        additional_auth_data: &[&[u8]],
        cipher_text: &[u8],
        plain_text: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Ok(srtp_aead_aes_128_gcm_decrypt(
            &self.key,
            iv,
            additional_auth_data,
            cipher_text,
            plain_text,
        )?)
    }
}
