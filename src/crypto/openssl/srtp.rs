//! SRTP cipher implementations using OpenSSL.

use openssl::cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::crypto::error::CryptoError;
use crate::crypto::provider::{AeadAes128Gcm, AeadAes128GcmCipher, AeadAes256Gcm};
use crate::crypto::provider::{AeadAes256GcmCipher, Aes128CmSha1_80Cipher};
use crate::crypto::provider::{SrtpProvider, SupportedAeadAes128Gcm};
use crate::crypto::provider::{SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};

// ============================================================================
// AES-128-CM-SHA1-80 Cipher
// ============================================================================

struct OsslAes128CmSha1_80Cipher {
    ctx: CipherCtx,
}

impl std::fmt::Debug for OsslAes128CmSha1_80Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslAes128CmSha1_80Cipher").finish()
    }
}

impl Aes128CmSha1_80Cipher for OsslAes128CmSha1_80Cipher {
    fn encrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.ctx.encrypt_init(None, None, Some(iv))?;
        let count = self.ctx.cipher_update(input, Some(output))?;
        self.ctx.cipher_final(&mut output[count..])?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.ctx.decrypt_init(None, None, Some(iv))?;
        let count = self.ctx.cipher_update(input, Some(output))?;
        self.ctx.cipher_final(&mut output[count..])?;
        Ok(())
    }
}

// ============================================================================
// AEAD-AES-128-GCM Cipher
// ============================================================================

struct OsslAeadAes128GcmCipher {
    ctx: CipherCtx,
}

impl std::fmt::Debug for OsslAeadAes128GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslAeadAes128GcmCipher").finish()
    }
}

impl AeadAes128GcmCipher for OsslAeadAes128GcmCipher {
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

        self.ctx.encrypt_init(None, None, Some(iv))?;
        let aad_c = self.ctx.cipher_update(aad, None)?;
        assert!(aad_c == aad.len());

        let count = self.ctx.cipher_update(input, Some(output))?;
        let final_count = self.ctx.cipher_final(&mut output[count..])?;

        let tag_offset = count + final_count;
        self.ctx
            .tag(&mut output[tag_offset..tag_offset + AeadAes128Gcm::TAG_LEN])?;

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

        let (cipher_text, tag) = input.split_at(input.len() - AeadAes128Gcm::TAG_LEN);

        self.ctx.decrypt_init(None, None, Some(iv))?;

        for aad in aads {
            self.ctx.cipher_update(aad, None)?;
        }

        self.ctx.set_tag(tag)?;

        let count = self.ctx.cipher_update(cipher_text, Some(output))?;
        let final_count = self.ctx.cipher_final(&mut output[count..])?;

        Ok(count + final_count)
    }
}

// ============================================================================
// AEAD-AES-256-GCM Cipher
// ============================================================================

struct OsslAeadAes256GcmCipher {
    ctx: CipherCtx,
}

impl std::fmt::Debug for OsslAeadAes256GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslAeadAes256GcmCipher").finish()
    }
}

impl AeadAes256GcmCipher for OsslAeadAes256GcmCipher {
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

        self.ctx.encrypt_init(None, None, Some(iv))?;
        let aad_c = self.ctx.cipher_update(aad, None)?;
        assert!(aad_c == aad.len());

        let count = self.ctx.cipher_update(input, Some(output))?;
        let final_count = self.ctx.cipher_final(&mut output[count..])?;

        let tag_offset = count + final_count;
        self.ctx
            .tag(&mut output[tag_offset..tag_offset + AeadAes256Gcm::TAG_LEN])?;

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

        let (cipher_text, tag) = input.split_at(input.len() - AeadAes256Gcm::TAG_LEN);

        self.ctx.decrypt_init(None, None, Some(iv))?;

        for aad in aads {
            self.ctx.cipher_update(aad, None)?;
        }

        self.ctx.set_tag(tag)?;

        let count = self.ctx.cipher_update(cipher_text, Some(output))?;
        let final_count = self.ctx.cipher_final(&mut output[count..])?;

        Ok(count + final_count)
    }
}

// ============================================================================
// SRTP Profile Support Implementations
// ============================================================================

struct OsslSupportedAes128CmSha1_80;

impl std::fmt::Debug for OsslSupportedAes128CmSha1_80 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslSupportedAes128CmSha1_80").finish()
    }
}

impl SupportedAes128CmSha1_80 for OsslSupportedAes128CmSha1_80 {
    fn create_cipher(&self, key: [u8; 16], encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        let t = cipher::Cipher::aes_128_ctr();
        let mut ctx = CipherCtx::new().expect("a reusable cipher context");

        if encrypt {
            ctx.encrypt_init(Some(t), Some(&key[..]), None)
                .expect("enc init");
        } else {
            ctx.decrypt_init(Some(t), Some(&key[..]), None)
                .expect("dec init");
        }

        Box::new(OsslAes128CmSha1_80Cipher { ctx })
    }
}

struct OsslSupportedAeadAes128Gcm;

impl std::fmt::Debug for OsslSupportedAeadAes128Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslSupportedAeadAes128Gcm").finish()
    }
}

impl SupportedAeadAes128Gcm for OsslSupportedAeadAes128Gcm {
    fn create_cipher(&self, key: [u8; 16], encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        let t = cipher::Cipher::aes_128_gcm();
        let mut ctx = CipherCtx::new().expect("a reusable cipher context");

        if encrypt {
            ctx.encrypt_init(Some(t), Some(&key), None)
                .expect("enc init");
            ctx.set_iv_length(AeadAes128Gcm::IV_LEN).expect("IV length");
            ctx.set_padding(false);
        } else {
            ctx.decrypt_init(Some(t), Some(&key), None)
                .expect("dec init");
        }

        Box::new(OsslAeadAes128GcmCipher { ctx })
    }
}

struct OsslSupportedAeadAes256Gcm;

impl std::fmt::Debug for OsslSupportedAeadAes256Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslSupportedAeadAes256Gcm").finish()
    }
}

impl SupportedAeadAes256Gcm for OsslSupportedAeadAes256Gcm {
    fn create_cipher(&self, key: [u8; 32], encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        let t = cipher::Cipher::aes_256_gcm();
        let mut ctx = CipherCtx::new().expect("a reusable cipher context");

        if encrypt {
            ctx.encrypt_init(Some(t), Some(&key), None)
                .expect("enc init");
            ctx.set_iv_length(AeadAes256Gcm::IV_LEN).expect("IV length");
            ctx.set_padding(false);
        } else {
            ctx.decrypt_init(Some(t), Some(&key), None)
                .expect("dec init");
        }

        Box::new(OsslAeadAes256GcmCipher { ctx })
    }
}

// ============================================================================
// SRTP Provider Implementation
// ============================================================================

pub(super) struct OsslSrtpProvider;

impl std::fmt::Debug for OsslSrtpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsslSrtpProvider").finish()
    }
}

impl SrtpProvider for OsslSrtpProvider {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &OsslSupportedAes128CmSha1_80
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &OsslSupportedAeadAes128Gcm
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &OsslSupportedAeadAes256Gcm
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        let mut aes =
            Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).expect("AES deriver");

        let count = aes.update(input, output).expect("AES update");
        let rest = aes.finalize(&mut output[count..]).expect("AES finalize");

        assert_eq!(count + rest, 16 + 16);
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        let mut aes =
            Crypter::new(Cipher::aes_256_ecb(), Mode::Encrypt, key, None).expect("AES deriver");

        let count = aes.update(input, output).expect("AES update");
        let rest = aes.finalize(&mut output[count..]).expect("AES finalize");

        assert_eq!(count + rest, 16 + 16);
    }
}
