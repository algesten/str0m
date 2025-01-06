use openssl::cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::crypto::srtp::SrtpCryptoImpl;
use crate::crypto::srtp::{aead_aes_128_gcm, aes_128_cm_sha1_80};
use crate::crypto::CryptoError;

pub struct OsslSrtpCryptoImpl;

impl SrtpCryptoImpl for OsslSrtpCryptoImpl {
    type Aes128CmSha1_80 = OsslAes128CmSha1_80;
    type AeadAes128Gcm = OsslAeadAes128Gcm;

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        let mut aes =
            Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).expect("AES deriver");

        // Run AES
        let count = aes.update(input, output).expect("AES update");
        let rest = aes.finalize(&mut output[count..]).expect("AES finalize");

        assert_eq!(count + rest, 16 + 16); // input len + block size
    }
}

pub struct OsslAes128CmSha1_80(CipherCtx);

impl aes_128_cm_sha1_80::CipherCtx for OsslAes128CmSha1_80 {
    fn new(key: aes_128_cm_sha1_80::AesKey, encrypt: bool) -> Self
    where
        Self: Sized,
    {
        let t = cipher::Cipher::aes_128_ctr();
        let mut ctx = CipherCtx::new().expect("a reusable cipher context");

        if encrypt {
            ctx.encrypt_init(Some(t), Some(&key[..]), None)
                .expect("enc init");
        } else {
            ctx.decrypt_init(Some(t), Some(&key[..]), None)
                .expect("enc init");
        }

        OsslAes128CmSha1_80(ctx)
    }

    fn encrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.0.encrypt_init(None, None, Some(iv))?;
        let count = self.0.cipher_update(input, Some(output))?;
        self.0.cipher_final(&mut output[count..])?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &aes_128_cm_sha1_80::RtpIv,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.0.decrypt_init(None, None, Some(iv))?;
        let count = self.0.cipher_update(input, Some(output))?;
        self.0.cipher_final(&mut output[count..])?;
        Ok(())
    }
}

pub struct OsslAeadAes128Gcm(CipherCtx);

impl aead_aes_128_gcm::CipherCtx for OsslAeadAes128Gcm {
    fn new(key: aead_aes_128_gcm::AeadKey, encrypt: bool) -> Self
    where
        Self: Sized,
    {
        let t = cipher::Cipher::aes_128_gcm();
        let mut ctx = CipherCtx::new().expect("a reusable cipher context");

        if encrypt {
            ctx.encrypt_init(Some(t), Some(&key), None)
                .expect("enc init");
            ctx.set_iv_length(aead_aes_128_gcm::IV_LEN)
                .expect("IV length");
            ctx.set_padding(false);
        } else {
            ctx.decrypt_init(Some(t), Some(&key), None)
                .expect("dec init");
        }

        OsslAeadAes128Gcm(ctx)
    }

    fn encrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        assert!(
            aad.len() >= 12,
            "Associated data length MUST be at least 12 octets"
        );

        // Set the IV
        self.0.encrypt_init(None, None, Some(iv))?;

        // Add the additional authenticated data, omitting the output argument informs
        // OpenSSL that we are providing AAD.
        let aad_c = self.0.cipher_update(aad, None)?;
        // TODO: This should maybe be an error
        assert!(aad_c == aad.len());

        let count = self.0.cipher_update(input, Some(output))?;
        let final_count = self.0.cipher_final(&mut output[count..])?;

        // Get the authentication tag and append it to the output
        let tag_offset = count + final_count;
        self.0
            .tag(&mut output[tag_offset..tag_offset + aead_aes_128_gcm::TAG_LEN])?;

        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; aead_aes_128_gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        // This needs to be converted to an error maybe
        assert!(input.len() >= aead_aes_128_gcm::TAG_LEN);

        let (cipher_text, tag) = input.split_at(input.len() - aead_aes_128_gcm::TAG_LEN);

        self.0.decrypt_init(None, None, Some(iv))?;

        // Add the additional authenticated data, omitting the output argument informs
        // OpenSSL that we are providing AAD.
        // With this the authentication tag will be verified.
        for aad in aads {
            self.0.cipher_update(aad, None)?;
        }

        self.0.set_tag(tag)?;

        let count = self.0.cipher_update(cipher_text, Some(output))?;

        let final_count = self.0.cipher_final(&mut output[count..])?;

        Ok(count + final_count)
    }
}
