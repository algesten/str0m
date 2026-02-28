//! Cipher suite implementations using OpenSSL.

use dimpl::crypto::SupportedDtls12CipherSuite;
use dimpl::crypto::SupportedDtls13CipherSuite;
use dimpl::crypto::{Aad, Cipher, Dtls12CipherSuite, HashAlgorithm, Nonce};
use dimpl::crypto::{Buf, Dtls13CipherSuite, TmpBuf};

use openssl::cipher::CipherRef;
use openssl::cipher_ctx::CipherCtx;

const AES_GCM_TAG_LEN: usize = 16;

// ============================================================================
// Shared AEAD helpers
// ============================================================================

/// Encrypt plaintext in-place using an AEAD cipher, appending the authentication tag.
fn aead_encrypt(
    cipher: &CipherRef,
    key: &[u8],
    plaintext: &mut Buf,
    aad: Aad,
    nonce: Nonce,
    tag_len: usize,
) -> Result<(), String> {
    debug_assert!(tag_len <= 16);

    let mut ctx = CipherCtx::new().map_err(|e| format!("{e}"))?;

    ctx.encrypt_init(Some(cipher), Some(key), Some(&nonce))
        .map_err(|e| format!("{e}"))?;

    ctx.cipher_update(&aad, None).map_err(|e| format!("{e}"))?;

    // OpenSSL may write up to block_size extra bytes during cipher_update/cipher_final.
    let mut ciphertext = vec![0u8; plaintext.len() + tag_len + 16];
    let count = ctx
        .cipher_update(plaintext, Some(&mut ciphertext))
        .map_err(|e| format!("{e}"))?;
    let final_count = ctx
        .cipher_final(&mut ciphertext[count..])
        .map_err(|e| format!("{e}"))?;

    let ct_len = count + final_count;

    let mut tag = [0u8; 16];
    ctx.tag(&mut tag[..tag_len]).map_err(|e| format!("{e}"))?;

    plaintext.clear();
    plaintext.extend_from_slice(&ciphertext[..ct_len]);
    plaintext.extend_from_slice(&tag[..tag_len]);
    Ok(())
}

/// Decrypt ciphertext in-place using an AEAD cipher, verifying the authentication tag.
fn aead_decrypt(
    cipher: &CipherRef,
    key: &[u8],
    ciphertext: &mut TmpBuf,
    aad: Aad,
    nonce: Nonce,
    tag_len: usize,
) -> Result<(), String> {
    if ciphertext.len() < tag_len {
        return Err("Ciphertext too short for authentication tag".into());
    }

    let ct_len = ciphertext.len() - tag_len;
    let (ct, tag) = ciphertext.as_ref().split_at(ct_len);

    let mut ctx = CipherCtx::new().map_err(|e| format!("{e}"))?;

    ctx.decrypt_init(Some(cipher), Some(key), Some(&nonce))
        .map_err(|e| format!("{e}"))?;

    ctx.cipher_update(&aad, None).map_err(|e| format!("{e}"))?;

    // OpenSSL may write up to block_size extra bytes during cipher_update/cipher_final.
    let mut plaintext = vec![0u8; ct_len + 16];
    let count = ctx
        .cipher_update(ct, Some(&mut plaintext))
        .map_err(|e| format!("{e}"))?;

    ctx.set_tag(tag).map_err(|e| format!("{e}"))?;

    let final_count = ctx
        .cipher_final(&mut plaintext[count..])
        .map_err(|e| format!("{e}"))?;

    let pt_len = count + final_count;
    ciphertext.truncate(pt_len);
    ciphertext.as_mut().copy_from_slice(&plaintext[..pt_len]);
    Ok(())
}

// ============================================================================
// AES-GCM
// ============================================================================

/// AES-GCM cipher implementation using OpenSSL.
///
/// Uses a fixed-size `[u8; 32]` buffer (the max AES key size) with a length
/// field so the key lives on the stack and can be reliably zeroed on drop.
struct AesGcm {
    key: [u8; 32],
    key_len: usize,
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
        let mut buf = [0u8; 32];
        buf[..key.len()].copy_from_slice(key);
        Ok(Self {
            key: buf,
            key_len: key.len(),
        })
    }

    fn key_bytes(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    fn cipher(&self) -> &'static CipherRef {
        if self.key_len == 16 {
            openssl::cipher::Cipher::aes_128_gcm()
        } else {
            openssl::cipher::Cipher::aes_256_gcm()
        }
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        for b in self.key.iter_mut() {
            // SAFETY: Volatile write prevents the compiler from eliding this zeroing.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl Cipher for AesGcm {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        aead_encrypt(
            self.cipher(),
            self.key_bytes(),
            plaintext,
            aad,
            nonce,
            AES_GCM_TAG_LEN,
        )
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        aead_decrypt(
            self.cipher(),
            self.key_bytes(),
            ciphertext,
            aad,
            nonce,
            AES_GCM_TAG_LEN,
        )
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
        AES_GCM_TAG_LEN
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
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
        AES_GCM_TAG_LEN
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

/// Static instances of supported DTLS 1.2 cipher suites.
static AES_128_GCM_SHA256: Aes128GcmSha256 = Aes128GcmSha256;
static AES_256_GCM_SHA384: Aes256GcmSha384 = Aes256GcmSha384;

/// All supported DTLS 1.2 cipher suites.
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

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
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

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
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
pub(super) static ALL_DTLS13_CIPHER_SUITES: &[&dyn SupportedDtls13CipherSuite] = &[
    &TLS13_AES_128_GCM_SHA256,
    &TLS13_AES_256_GCM_SHA384,
    &TLS13_CHACHA20_POLY1305_SHA256,
];

// ============================================================================
// ChaCha20-Poly1305 AEAD (DTLS 1.3)
// ============================================================================

const CHACHA20_POLY1305_TAG_LEN: usize = 16;
const CHACHA20_POLY1305_KEY_LEN: usize = 32;
const CHACHA20_POLY1305_IV_LEN: usize = 12;

/// ChaCha20-Poly1305 cipher implementation using OpenSSL.
struct ChaCha20Poly1305 {
    key: [u8; CHACHA20_POLY1305_KEY_LEN],
}

impl std::fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Poly1305").finish_non_exhaustive()
    }
}

impl ChaCha20Poly1305 {
    fn new(key: &[u8]) -> Result<Self, String> {
        let key: [u8; CHACHA20_POLY1305_KEY_LEN] = key
            .try_into()
            .map_err(|_| format!("Invalid key size for ChaCha20-Poly1305: {}", key.len()))?;
        Ok(Self { key })
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        for b in self.key.iter_mut() {
            // SAFETY: Volatile write prevents the compiler from eliding this zeroing.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl Cipher for ChaCha20Poly1305 {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        aead_encrypt(
            openssl::cipher::Cipher::chacha20_poly1305(),
            &self.key,
            plaintext,
            aad,
            nonce,
            CHACHA20_POLY1305_TAG_LEN,
        )
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        aead_decrypt(
            openssl::cipher::Cipher::chacha20_poly1305(),
            &self.key,
            ciphertext,
            aad,
            nonce,
            CHACHA20_POLY1305_TAG_LEN,
        )
    }
}

/// TLS_CHACHA20_POLY1305_SHA256 cipher suite (TLS 1.3 / DTLS 1.3).
#[derive(Debug)]
struct Tls13ChaCha20Poly1305Sha256;

impl SupportedDtls13CipherSuite for Tls13ChaCha20Poly1305Sha256 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::CHACHA20_POLY1305_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_len(&self) -> usize {
        CHACHA20_POLY1305_KEY_LEN
    }

    fn iv_len(&self) -> usize {
        CHACHA20_POLY1305_IV_LEN
    }

    fn tag_len(&self) -> usize {
        CHACHA20_POLY1305_TAG_LEN
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(ChaCha20Poly1305::new(key)?))
    }

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        if sn_key.len() != 32 {
            panic!(
                "encrypt_sn: invalid ChaCha20 key length {} (expected 32)",
                sn_key.len()
            );
        }
        // RFC 9147 Section 4.2.3 / RFC 9001 Section 5.4.4: For ChaCha20-Poly1305,
        // the mask is generated by treating the sample as a nonce for ChaCha20
        // with a zero block counter and encrypting zero bytes.
        let cipher = openssl::cipher::Cipher::chacha20();
        let mut ctx = CipherCtx::new().expect("CipherCtx::new");
        ctx.encrypt_init(Some(cipher), Some(sn_key), Some(sample))
            .expect("encrypt_init");

        let mut output = [0u8; 32];
        let input = [0u8; 16];
        let count = ctx
            .cipher_update(&input, Some(&mut output))
            .expect("cipher_update");
        let final_count = ctx
            .cipher_final(&mut output[count..])
            .expect("cipher_final");
        debug_assert_eq!(
            count + final_count,
            16,
            "ChaCha20 stream cipher should not pad"
        );

        let mut result = [0u8; 16];
        result.copy_from_slice(&output[..16]);
        result
    }
}

static TLS13_CHACHA20_POLY1305_SHA256: Tls13ChaCha20Poly1305Sha256 = Tls13ChaCha20Poly1305Sha256;

/// AES-ECB single block encryption for record number protection.
fn aes_ecb_encrypt(key: &[u8], input: &[u8; 16]) -> [u8; 16] {
    let cipher = match key.len() {
        16 => openssl::cipher::Cipher::aes_128_ecb(),
        32 => openssl::cipher::Cipher::aes_256_ecb(),
        n => panic!("aes_ecb_encrypt: invalid AES key length {n} (expected 16 or 32)"),
    };

    let mut ctx = CipherCtx::new().expect("CipherCtx::new");
    ctx.encrypt_init(Some(cipher), Some(key), None)
        .expect("encrypt_init");
    ctx.set_padding(false);

    let mut output = [0u8; 32]; // Extra space for block cipher
    let count = ctx
        .cipher_update(input, Some(&mut output))
        .expect("cipher_update");
    let final_count = ctx
        .cipher_final(&mut output[count..])
        .expect("cipher_final");
    debug_assert_eq!(
        count + final_count,
        16,
        "AES-ECB should produce exactly one block"
    );

    let mut result = [0u8; 16];
    result.copy_from_slice(&output[..16]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use dimpl::crypto::Cipher;

    #[test]
    fn aes128_gcm_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"hello world, this is a test message for AES-GCM";

        let mut cipher = AesGcm::new(&key).unwrap();

        // Encrypt
        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        // Ciphertext should be plaintext_len + 16 (tag)
        assert_eq!(buf.len(), plaintext.len() + AES_GCM_TAG_LEN);
        // Should differ from plaintext
        assert_ne!(&buf.as_ref()[..plaintext.len()], &plaintext[..]);

        // Decrypt
        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.as_ref(), plaintext);
    }

    #[test]
    fn aes256_gcm_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = Nonce([0x02u8; 12]);
        let plaintext = b"AES-256-GCM test";

        let mut cipher = AesGcm::new(&key).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.as_ref(), plaintext);
    }

    #[test]
    fn aes_gcm_wrong_key_fails_decrypt() {
        let key1 = [0x42u8; 16];
        let key2 = [0x43u8; 16];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"secret";

        let mut cipher1 = AesGcm::new(&key1).unwrap();
        let mut cipher2 = AesGcm::new(&key2).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher1
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(
            cipher2
                .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
                .is_err()
        );
    }

    #[test]
    fn aes_gcm_invalid_key_size_rejected() {
        assert!(AesGcm::new(&[0u8; 15]).is_err());
        assert!(AesGcm::new(&[0u8; 24]).is_err());
        assert!(AesGcm::new(&[0u8; 16]).is_ok());
        assert!(AesGcm::new(&[0u8; 32]).is_ok());
    }

    #[test]
    fn aes_ecb_encrypt_deterministic() {
        let key = [0u8; 16];
        let input = [0u8; 16];
        let result = aes_ecb_encrypt(&key, &input);
        assert_eq!(result.len(), 16);
        // Different input produces different output
        let input2 = [0x01u8; 16];
        let result2 = aes_ecb_encrypt(&key, &input2);
        assert_ne!(result, result2);
    }

    #[test]
    fn chacha20_poly1305_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"hello world, this is a test for ChaCha20-Poly1305";

        let mut cipher = ChaCha20Poly1305::new(&key).unwrap();

        // Encrypt
        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        // Ciphertext should be plaintext_len + 16 (tag)
        assert_eq!(buf.len(), plaintext.len() + CHACHA20_POLY1305_TAG_LEN);
        assert_ne!(&buf.as_ref()[..plaintext.len()], &plaintext[..]);

        // Decrypt
        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.as_ref(), plaintext);
    }

    #[test]
    fn chacha20_poly1305_wrong_key_fails_decrypt() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"secret";

        let mut cipher1 = ChaCha20Poly1305::new(&key1).unwrap();
        let mut cipher2 = ChaCha20Poly1305::new(&key2).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher1
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(
            cipher2
                .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
                .is_err()
        );
    }

    #[test]
    fn chacha20_poly1305_invalid_key_size_rejected() {
        assert!(ChaCha20Poly1305::new(&[0u8; 16]).is_err());
        assert!(ChaCha20Poly1305::new(&[0u8; 31]).is_err());
        assert!(ChaCha20Poly1305::new(&[0u8; 32]).is_ok());
    }

    use crate::dimpl_provider::test_utils::hex_to_vec as hex;

    /// RFC 8439 Section 2.8.2 — AEAD construction test vector.
    #[test]
    fn chacha20_poly1305_rfc8439_aead_test_vector() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce_bytes = hex("070000004041424344454647");
        let aad_bytes = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_ciphertext = hex("d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b\
             6116");
        let expected_tag = hex("1ae10b594f09e26a7e902ecbd0600691");

        let nonce = Nonce(nonce_bytes.as_slice().try_into().unwrap());
        let mut aad_arr = arrayvec::ArrayVec::<u8, 13>::new();
        aad_arr.try_extend_from_slice(&aad_bytes).unwrap();

        let mut cipher = ChaCha20Poly1305::new(&key).unwrap();

        // Encrypt
        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher.encrypt(&mut buf, Aad(aad_arr), nonce).unwrap();

        // Verify ciphertext (excluding tag)
        let ct_len = buf.len() - CHACHA20_POLY1305_TAG_LEN;
        assert_eq!(&buf.as_ref()[..ct_len], &expected_ciphertext[..]);
        // Verify tag
        assert_eq!(&buf.as_ref()[ct_len..], &expected_tag[..]);

        // Verify decrypt roundtrip
        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        let mut aad_arr2 = arrayvec::ArrayVec::<u8, 13>::new();
        aad_arr2.try_extend_from_slice(&aad_bytes).unwrap();
        cipher.decrypt(&mut tmp, Aad(aad_arr2), nonce).unwrap();
        assert_eq!(tmp.as_ref(), plaintext);
    }

    /// Verify that modifying the AAD causes decryption to fail.
    #[test]
    fn chacha20_poly1305_aad_tamper_detected() {
        let key = [0x42u8; 32];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"authenticated data test";

        let mut cipher = ChaCha20Poly1305::new(&key).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);

        cipher
            .encrypt(&mut buf, Aad([0x00u8; 13].into()), nonce)
            .unwrap();

        // Tamper with AAD
        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(
            cipher
                .decrypt(&mut tmp, Aad([0x01u8; 13].into()), nonce)
                .is_err()
        );
    }

    /// Verify that a wrong nonce causes decryption to fail.
    #[test]
    fn chacha20_poly1305_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let nonce1 = Nonce([0x01u8; 12]);
        let nonce2 = Nonce([0x02u8; 12]);
        let plaintext = b"nonce test";

        let mut cipher = ChaCha20Poly1305::new(&key).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce1)
            .unwrap();

        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(
            cipher
                .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce2)
                .is_err()
        );
    }

    /// Corrupted ciphertext tag byte should cause decryption failure.
    #[test]
    fn chacha20_poly1305_tag_corruption_detected() {
        let key = [0x42u8; 32];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"tag corruption test";

        let mut cipher = ChaCha20Poly1305::new(&key).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        // Flip a bit in the last byte (inside the tag)
        let mut backing = buf.as_ref().to_vec();
        let last = backing.len() - 1;
        backing[last] ^= 0x01;
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(
            cipher
                .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
                .is_err()
        );
    }

    /// Corrupted ciphertext body byte should cause decryption failure.
    #[test]
    fn chacha20_poly1305_ciphertext_corruption_detected() {
        let key = [0x42u8; 32];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"ciphertext corruption test";

        let mut cipher = ChaCha20Poly1305::new(&key).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        // Flip a bit in the first ciphertext byte
        let mut backing = buf.as_ref().to_vec();
        backing[0] ^= 0x01;
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(
            cipher
                .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
                .is_err()
        );
    }

    /// Empty plaintext should produce tag-only output.
    #[test]
    fn chacha20_poly1305_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = Nonce([0x01u8; 12]);

        let mut cipher = ChaCha20Poly1305::new(&key).unwrap();

        let mut buf = Buf::new();
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        // Should be exactly the tag length
        assert_eq!(buf.len(), CHACHA20_POLY1305_TAG_LEN);

        // Decrypt back to empty
        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.len(), 0);
    }

    /// Truncated ciphertext (shorter than tag) should fail.
    #[test]
    fn chacha20_poly1305_truncated_ciphertext_rejected() {
        let key = [0x42u8; 32];
        let nonce = Nonce([0x01u8; 12]);

        let mut cipher = ChaCha20Poly1305::new(&key).unwrap();

        let mut backing = vec![0u8; 8]; // less than 16 byte tag
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(
            cipher
                .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
                .is_err()
        );
    }

    /// Same test for AES-GCM: AAD tamper detected.
    #[test]
    fn aes_gcm_aad_tamper_detected() {
        let key = [0x42u8; 16];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"authenticated data test";

        let mut cipher = AesGcm::new(&key).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0x00u8; 13].into()), nonce)
            .unwrap();

        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(
            cipher
                .decrypt(&mut tmp, Aad([0x01u8; 13].into()), nonce)
                .is_err()
        );
    }

    /// Same test for AES-GCM: wrong nonce fails.
    #[test]
    fn aes_gcm_wrong_nonce_fails() {
        let key = [0x42u8; 16];
        let nonce1 = Nonce([0x01u8; 12]);
        let nonce2 = Nonce([0x02u8; 12]);
        let plaintext = b"nonce test";

        let mut cipher = AesGcm::new(&key).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce1)
            .unwrap();

        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(
            cipher
                .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce2)
                .is_err()
        );
    }

    /// AES-GCM tag corruption should fail decrypt.
    #[test]
    fn aes_gcm_tag_corruption_detected() {
        let key = [0x42u8; 16];
        let nonce = Nonce([0x01u8; 12]);
        let plaintext = b"tag test";

        let mut cipher = AesGcm::new(&key).unwrap();

        let mut buf = Buf::new();
        buf.extend_from_slice(plaintext);
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();

        let mut backing = buf.as_ref().to_vec();
        let last = backing.len() - 1;
        backing[last] ^= 0x01;
        let mut tmp = TmpBuf::new(&mut backing);
        assert!(
            cipher
                .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
                .is_err()
        );
    }

    /// AES-GCM empty plaintext roundtrip.
    #[test]
    fn aes_gcm_empty_plaintext() {
        let key = [0x42u8; 16];
        let nonce = Nonce([0x01u8; 12]);

        let mut cipher = AesGcm::new(&key).unwrap();

        let mut buf = Buf::new();
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(buf.len(), AES_GCM_TAG_LEN);

        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.len(), 0);
    }

    /// AES-ECB known-answer test (NIST FIPS 197 Appendix B).
    #[test]
    fn aes_ecb_nist_fips197_appendix_b() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let input: [u8; 16] = hex("3243f6a8885a308d313198a2e0370734").try_into().unwrap();
        let expected = hex("3925841d02dc09fbdc118597196a0b32");

        let result = aes_ecb_encrypt(&key, &input);
        assert_eq!(&result[..], &expected[..]);
    }

    /// SN encryption for DTLS 1.3 cipher suites should be deterministic.
    #[test]
    fn tls13_cipher_suites_encrypt_sn_deterministic() {
        let sn_key = [0x42u8; 16];
        let sample: [u8; 16] = [0x01u8; 16];

        let result_128 = TLS13_AES_128_GCM_SHA256.encrypt_sn(&sn_key, &sample);
        let result_128b = TLS13_AES_128_GCM_SHA256.encrypt_sn(&sn_key, &sample);
        assert_eq!(result_128, result_128b);

        let sn_key_32 = [0x42u8; 32];
        let result_chacha = TLS13_CHACHA20_POLY1305_SHA256.encrypt_sn(&sn_key_32, &sample);
        let result_chacha_b = TLS13_CHACHA20_POLY1305_SHA256.encrypt_sn(&sn_key_32, &sample);
        assert_eq!(result_chacha, result_chacha_b);
    }

    /// RFC 9001 Appendix A.5 ChaCha20 header protection test vector.
    #[test]
    fn tls13_chacha20_encrypt_sn_rfc9001_vector() {
        let sn_key: [u8; 32] = [
            0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc,
            0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b,
            0x0a, 0xb7, 0xa7, 0xa4,
        ];
        let sample: [u8; 16] = [
            0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a,
            0x5b, 0xfb,
        ];

        let mask = TLS13_CHACHA20_POLY1305_SHA256.encrypt_sn(&sn_key, &sample);
        assert_eq!(&mask[..5], &[0xae, 0xfe, 0xfe, 0x7d, 0x03]);
    }

    /// Verify DTLS 1.3 suite metadata is consistent.
    #[test]
    fn tls13_chacha20_suite_metadata() {
        assert_eq!(
            TLS13_CHACHA20_POLY1305_SHA256.suite(),
            Dtls13CipherSuite::CHACHA20_POLY1305_SHA256
        );
        assert_eq!(
            TLS13_CHACHA20_POLY1305_SHA256.hash_algorithm(),
            HashAlgorithm::SHA256
        );
        assert_eq!(TLS13_CHACHA20_POLY1305_SHA256.key_len(), 32);
        assert_eq!(TLS13_CHACHA20_POLY1305_SHA256.iv_len(), 12);
        assert_eq!(TLS13_CHACHA20_POLY1305_SHA256.tag_len(), 16);
    }

    /// Verify DTLS 1.3 AES suite metadata.
    #[test]
    fn tls13_aes128_suite_metadata() {
        assert_eq!(
            TLS13_AES_128_GCM_SHA256.suite(),
            Dtls13CipherSuite::AES_128_GCM_SHA256
        );
        assert_eq!(
            TLS13_AES_128_GCM_SHA256.hash_algorithm(),
            HashAlgorithm::SHA256
        );
        assert_eq!(TLS13_AES_128_GCM_SHA256.key_len(), 16);
        assert_eq!(TLS13_AES_128_GCM_SHA256.iv_len(), 12);
        assert_eq!(TLS13_AES_128_GCM_SHA256.tag_len(), 16);
    }

    #[test]
    fn tls13_aes256_suite_metadata() {
        assert_eq!(
            TLS13_AES_256_GCM_SHA384.suite(),
            Dtls13CipherSuite::AES_256_GCM_SHA384
        );
        assert_eq!(
            TLS13_AES_256_GCM_SHA384.hash_algorithm(),
            HashAlgorithm::SHA384
        );
        assert_eq!(TLS13_AES_256_GCM_SHA384.key_len(), 32);
        assert_eq!(TLS13_AES_256_GCM_SHA384.iv_len(), 12);
        assert_eq!(TLS13_AES_256_GCM_SHA384.tag_len(), 16);
    }

    /// All DTLS 1.3 suites in the static list should have distinct ids.
    #[test]
    fn all_dtls13_suites_unique() {
        let suites: Vec<_> = ALL_DTLS13_CIPHER_SUITES.iter().map(|s| s.suite()).collect();
        for (i, a) in suites.iter().enumerate() {
            for b in &suites[i + 1..] {
                assert_ne!(a, b, "duplicate DTLS 1.3 cipher suite");
            }
        }
    }

    /// All DTLS 1.2 suites in the static list should have distinct ids.
    #[test]
    fn all_dtls12_suites_unique() {
        let suites: Vec<_> = ALL_CIPHER_SUITES.iter().map(|s| s.suite()).collect();
        for (i, a) in suites.iter().enumerate() {
            for b in &suites[i + 1..] {
                assert_ne!(a, b, "duplicate DTLS 1.2 cipher suite");
            }
        }
    }

    /// Verify DTLS 1.2 AES-128-GCM-SHA256 suite metadata.
    #[test]
    fn dtls12_aes128_suite_metadata() {
        assert_eq!(
            AES_128_GCM_SHA256.suite(),
            Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
        );
        assert_eq!(AES_128_GCM_SHA256.hash_algorithm(), HashAlgorithm::SHA256);
        assert_eq!(AES_128_GCM_SHA256.key_lengths(), (0, 16, 4));
    }

    /// Verify DTLS 1.2 AES-256-GCM-SHA384 suite metadata.
    #[test]
    fn dtls12_aes256_suite_metadata() {
        assert_eq!(
            AES_256_GCM_SHA384.suite(),
            Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
        );
        assert_eq!(AES_256_GCM_SHA384.hash_algorithm(), HashAlgorithm::SHA384);
        assert_eq!(AES_256_GCM_SHA384.key_lengths(), (0, 32, 4));
    }

    /// AES-256 encrypt_sn should be deterministic.
    #[test]
    fn tls13_aes256_encrypt_sn_deterministic() {
        let sn_key = [0x42u8; 32];
        let sample: [u8; 16] = [0x01u8; 16];
        let result = TLS13_AES_256_GCM_SHA384.encrypt_sn(&sn_key, &sample);
        let result_b = TLS13_AES_256_GCM_SHA384.encrypt_sn(&sn_key, &sample);
        assert_eq!(result, result_b);
    }

    /// Exercise create_cipher factory for DTLS 1.2 suites.
    #[test]
    fn dtls12_create_cipher_roundtrip() {
        let nonce = Nonce([0x01u8; 12]);

        // AES-128-GCM via factory
        let mut cipher = AES_128_GCM_SHA256.create_cipher(&[0x42u8; 16]).unwrap();
        let mut buf = Buf::new();
        buf.extend_from_slice(b"factory test");
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();
        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.as_ref(), b"factory test");

        // AES-256-GCM via factory
        let mut cipher = AES_256_GCM_SHA384.create_cipher(&[0x42u8; 32]).unwrap();
        let mut buf = Buf::new();
        buf.extend_from_slice(b"factory test 256");
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();
        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.as_ref(), b"factory test 256");
    }

    /// Exercise create_cipher factory for DTLS 1.3 suites.
    #[test]
    fn dtls13_create_cipher_roundtrip() {
        let nonce = Nonce([0x01u8; 12]);

        // AES-128-GCM via factory
        let mut cipher = TLS13_AES_128_GCM_SHA256
            .create_cipher(&[0x42u8; 16])
            .unwrap();
        let mut buf = Buf::new();
        buf.extend_from_slice(b"dtls13 factory");
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();
        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.as_ref(), b"dtls13 factory");

        // ChaCha20-Poly1305 via factory
        let mut cipher = TLS13_CHACHA20_POLY1305_SHA256
            .create_cipher(&[0x42u8; 32])
            .unwrap();
        let mut buf = Buf::new();
        buf.extend_from_slice(b"dtls13 chacha");
        cipher
            .encrypt(&mut buf, Aad([0u8; 13].into()), nonce)
            .unwrap();
        let mut backing = buf.as_ref().to_vec();
        let mut tmp = TmpBuf::new(&mut backing);
        cipher
            .decrypt(&mut tmp, Aad([0u8; 13].into()), nonce)
            .unwrap();
        assert_eq!(tmp.as_ref(), b"dtls13 chacha");
    }
}
