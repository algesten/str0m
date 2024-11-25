use crate::crypto::srtp::SrtpCryptoImpl;
use crate::crypto::srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80};
use crate::crypto::CryptoError;
use str0m_wincrypto::{
    wincrypto_srtp_aead_aes_128_gcm_decrypt, wincrypto_srtp_aead_aes_128_gcm_encrypt,
    wincrypto_srtp_aes_128_cm, wincrypto_srtp_aes_128_ecb_round, WinCryptoSrtpKey,
};

pub struct WinCryptoSrtpCryptoImpl;

impl SrtpCryptoImpl for WinCryptoSrtpCryptoImpl {
    type Aes128CmSha1_80 = WinCryptoAes128CmSha1_80;
    type AeadAes128Gcm = WinCryptoAeadAes128Gcm;

    fn srtp_aes_128_ecb_round(key: &[u8], input: &[u8], output: &mut [u8]) {
        let key = WinCryptoSrtpKey::create_aes_ecb_key(key).expect("AES key");
        let count = wincrypto_srtp_aes_128_ecb_round(&key, input, output).expect("AES encrypt");
        assert_eq!(count, 16 + 16); // block size
    }
}

pub struct WinCryptoAes128CmSha1_80 {
    key: WinCryptoSrtpKey,
}

impl aes_128_cm_sha1_80::CipherCtx for WinCryptoAes128CmSha1_80 {
    /// Create a new context for AES-128-CM-SHA1-80 encryption/decryption.
    ///
    /// The encrypt flag is ignored, since the same operation is used for both encryption and
    /// decryption.
    fn new(key: aes_128_cm_sha1_80::AesKey, _encrypt: bool) -> Self
    where
        Self: Sized,
    {
        Self {
            key: WinCryptoSrtpKey::create_aes_ctr_key(&key).expect("generate sym key"),
        }
    }

    fn encrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> Result<(), CryptoError> {
        wincrypto_srtp_aes_128_cm(&self.key, iv, plain_text, cipher_text)?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        cipher_text: &[u8],
        plain_text: &mut [u8],
    ) -> Result<(), CryptoError> {
        wincrypto_srtp_aes_128_cm(&self.key, iv, cipher_text, plain_text)?;
        Ok(())
    }
}

pub struct WinCryptoAeadAes128Gcm {
    key: WinCryptoSrtpKey,
}

impl aead_aes_128_gcm::CipherCtx for WinCryptoAeadAes128Gcm {
    /// Create a new context for AES-128-GCM encryption/decryption.
    ///
    /// The encrypt flag is ignored, since it is not needed and the same
    /// key can be used for both encryption and decryption.
    fn new(key: aead_aes_128_gcm::AeadKey, _encrypt: bool) -> Self
    where
        Self: Sized,
    {
        Self {
            key: WinCryptoSrtpKey::create_aes_gcm_key(&key).expect("generate sym key"),
        }
    }

    fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        additional_auth_data: &[u8],
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> Result<(), CryptoError> {
        wincrypto_srtp_aead_aes_128_gcm_encrypt(
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
        Ok(wincrypto_srtp_aead_aes_128_gcm_decrypt(
            &self.key,
            iv,
            additional_auth_data,
            cipher_text,
            plain_text,
        )?)
    }
}
