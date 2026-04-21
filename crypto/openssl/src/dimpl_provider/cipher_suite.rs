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
pub(super) fn aead_encrypt(
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
pub(super) fn aead_decrypt(
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
    #[cfg(not(feature = "fips140"))]
    &super::chacha20::TLS13_CHACHA20_POLY1305_SHA256,
];

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

    use crate::dimpl_provider::test_utils::hex_to_vec as hex;

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
    }
}
