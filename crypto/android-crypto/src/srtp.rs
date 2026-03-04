//! SRTP cipher implementations using Android JNI crypto.

use str0m_proto::crypto::SupportedAeadAes128Gcm;
use str0m_proto::crypto::{AeadAes128Gcm, AeadAes128GcmCipher, AeadAes256Gcm, AeadAes256GcmCipher};
use str0m_proto::crypto::{Aes128CmSha1_80Cipher, CryptoError, SrtpProvider};
use str0m_proto::crypto::{SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};

use crate::jni_crypto;

// AES-128-CM-SHA1-80 Cipher (CTR mode)

struct AndroidCryptoAes128CmSha1_80Cipher {
    key: [u8; 16],
}

impl std::fmt::Debug for AndroidCryptoAes128CmSha1_80Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCryptoAes128CmSha1_80Cipher")
            .finish()
    }
}

impl Aes128CmSha1_80Cipher for AndroidCryptoAes128CmSha1_80Cipher {
    fn encrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_ctr_round(&self.key, iv, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        // AES-CTR mode is symmetric, so we can use the same operation
        aes_ctr_round(&self.key, iv, input, output)
    }
}

// AEAD-AES-128-GCM Cipher

struct AndroidCryptoAeadAes128GcmCipher {
    key: [u8; 16],
}

impl std::fmt::Debug for AndroidCryptoAeadAes128GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCryptoAeadAes128GcmCipher").finish()
    }
}

impl AeadAes128GcmCipher for AndroidCryptoAeadAes128GcmCipher {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadAes128Gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_gcm_encrypt(&self.key, iv, input, aad, output)?;
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
        aes_gcm_decrypt(&self.key, iv, aads, input, output)
    }
}

// AEAD-AES-256-GCM Cipher

struct AndroidCryptoAeadAes256GcmCipher {
    key: [u8; 32],
}

impl std::fmt::Debug for AndroidCryptoAeadAes256GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCryptoAeadAes256GcmCipher").finish()
    }
}

impl AeadAes256GcmCipher for AndroidCryptoAeadAes256GcmCipher {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadAes256Gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_gcm_encrypt(&self.key, iv, input, aad, output)?;
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
        aes_gcm_decrypt(&self.key, iv, aads, input, output)
    }
}

fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    input: &[u8],
    aad: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    assert!(
        aad.len() >= 12,
        "Associated data length MUST be at least 12 octets"
    );

    jni_crypto::aes_gcm_encrypt(key, iv, input, aad, output)
}

fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    aads: &[&[u8]],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    static EMPTY: [u8; 0] = [];
    let aad = match aads.len() {
        0 => &EMPTY,
        1 => aads[0],
        _ => &aads.concat(),
    };

    jni_crypto::aes_gcm_decrypt(key, iv, input, aad, output)
}

// SRTP Profile Support Implementations

struct AndroidCryptoSupportedAes128CmSha1_80;

impl std::fmt::Debug for AndroidCryptoSupportedAes128CmSha1_80 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCryptoSupportedAes128CmSha1_80")
            .finish()
    }
}

impl SupportedAes128CmSha1_80 for AndroidCryptoSupportedAes128CmSha1_80 {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        Box::new(AndroidCryptoAes128CmSha1_80Cipher { key })
    }
}

struct AndroidCryptoSupportedAeadAes128Gcm;

impl std::fmt::Debug for AndroidCryptoSupportedAeadAes128Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCryptoSupportedAeadAes128Gcm")
            .finish()
    }
}

impl SupportedAeadAes128Gcm for AndroidCryptoSupportedAeadAes128Gcm {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        Box::new(AndroidCryptoAeadAes128GcmCipher { key })
    }
}

struct AndroidCryptoSupportedAeadAes256Gcm;

impl std::fmt::Debug for AndroidCryptoSupportedAeadAes256Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCryptoSupportedAeadAes256Gcm")
            .finish()
    }
}

impl SupportedAeadAes256Gcm for AndroidCryptoSupportedAeadAes256Gcm {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        Box::new(AndroidCryptoAeadAes256GcmCipher { key })
    }
}

// SRTP Provider Implementation

pub(crate) struct AndroidCryptoSrtpProvider;

impl std::fmt::Debug for AndroidCryptoSrtpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCryptoSrtpProvider").finish()
    }
}

impl SrtpProvider for AndroidCryptoSrtpProvider {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &AndroidCryptoSupportedAes128CmSha1_80
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &AndroidCryptoSupportedAeadAes128Gcm
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &AndroidCryptoSupportedAeadAes256Gcm
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        jni_crypto::aes_ecb_encrypt(key, input, output).unwrap();
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        jni_crypto::aes_ecb_encrypt(key, input, output).unwrap();
    }
}

// CTR implementation.
//
// This is not a generic CTR implementation, as it imposes a 2k limit on
// the input/output, which is more than enough for our SRTP use where each
// packet is smaller than the MTU.
//
// Note: If we need to support larger blocks, we could loop 2k at a time.
// However, CTR is frowned upon, it's only provided since it is a requirement
// for WebRTC, but in almost all cases AES-GCM should be used.
fn aes_ctr_round(
    key: &[u8],
    iv: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    // First, we'll make a copy of the IV with a countered as many times as
    // needed into a new countered_iv.
    let mut iv = *iv;
    let mut countered_iv = [0u8; 2048];
    let mut encrypted_countered_iv = [0u8; 2048];
    let mut offset = 0;
    while offset <= input.len() {
        let start = offset;
        let end = offset + 16;
        countered_iv[start..end].copy_from_slice(&iv);
        offset += 16;
        for idx in 0..16 {
            let n = iv[15 - idx];
            if n == 0xff {
                iv[15 - idx] = 0;
            } else {
                iv[15 - idx] += 1;
                break;
            }
        }
    }

    jni_crypto::aes_ecb_encrypt(
        key,
        &countered_iv[..offset],
        &mut encrypted_countered_iv[..offset],
    )?;

    // XOR the intermediate_output with the input
    for i in 0..input.len() {
        output[i] = input[i] ^ encrypted_countered_iv[i];
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use str0m_proto::crypto::SrtpProvider;

    // Test vectors from NIST SP 800-38A:
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

    fn hex_to_vec(hex: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..hex.len() / 2 {
            let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            v.push(byte);
        }
        v
    }

    fn slice_to_hex(data: &[u8]) -> String {
        let mut s = String::new();
        for byte in data.iter() {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }

    #[test]
    fn test_aes_128_ecb_nist_vector() {
        // F.1.1 ECB-AES128.Encrypt from NIST SP 800-38A
        let key = hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c");
        let plaintext = hex_to_vec("6bc1bee22e409f96e93d7e117393172a");
        let expected = hex_to_vec("3ad77bb40d7a3660a89ecaf32466ef97");

        let mut output = vec![0u8; 16];
        AndroidCryptoSrtpProvider.srtp_aes_128_ecb_round(&key, &plaintext, &mut output);

        assert_eq!(slice_to_hex(&output), slice_to_hex(&expected));
    }

    #[test]
    fn test_aes_128_ctr_nist_vector() {
        // F.5.1 CTR-AES128.Encrypt from NIST SP 800-38A
        let key = hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_vec("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = hex_to_vec("6bc1bee22e409f96e93d7e117393172a");
        let expected = hex_to_vec("874d6191b620e3261bef6864990db6ce");

        let mut output = vec![0u8; 16];
        let iv_array: [u8; 16] = iv.try_into().unwrap();
        aes_ctr_round(&key, &iv_array, &plaintext, &mut output).unwrap();

        assert_eq!(slice_to_hex(&output), slice_to_hex(&expected));
    }
}
