//! SRTP cipher implementations using Apple CommonCrypto.
use str0m_proto::crypto::SupportedAeadAes128Gcm;
use str0m_proto::crypto::{AeadAes128Gcm, AeadAes128GcmCipher, AeadAes256Gcm, AeadAes256GcmCipher};
use str0m_proto::crypto::{Aes128CmSha1_80Cipher, CryptoError, SrtpProvider};
use str0m_proto::crypto::{SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};

use crate::common_crypto;

// AES-128-CM-SHA1-80 Cipher (CTR mode)

struct AppleCryptoAes128CmSha1_80Cipher {
    key: [u8; 16],
}

impl std::fmt::Debug for AppleCryptoAes128CmSha1_80Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleCryptoAes128CmSha1_80Cipher").finish()
    }
}

impl Aes128CmSha1_80Cipher for AppleCryptoAes128CmSha1_80Cipher {
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

struct AppleCryptoAeadAes128GcmCipher {
    key: [u8; 16],
}

impl std::fmt::Debug for AppleCryptoAeadAes128GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleCryptoAeadAes128GcmCipher").finish()
    }
}

impl AeadAes128GcmCipher for AppleCryptoAeadAes128GcmCipher {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadAes128Gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_gcm_encrypt(&self.key, iv, input, aad, output)
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

struct AppleCryptoAeadAes256GcmCipher {
    key: [u8; 32],
}

impl std::fmt::Debug for AppleCryptoAeadAes256GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleCryptoAeadAes256GcmCipher").finish()
    }
}

impl AeadAes256GcmCipher for AppleCryptoAeadAes256GcmCipher {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadAes256Gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_gcm_encrypt(&self.key, iv, input, aad, output)
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
) -> Result<(), CryptoError> {
    assert!(
        aad.len() >= 12,
        "Associated data length MUST be at least 12 octets"
    );

    apple_cryptokit::symmetric::aes::aes_gcm_encrypt_to_with_aad(key, iv, input, aad, output)
        .map_err(|err| CryptoError::Other(format!("{err:?}")))?;

    Ok(())
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

    apple_cryptokit::symmetric::aes::aes_gcm_decrypt_to_with_aad(key, iv, input, aad, output)
        .map_err(|err| CryptoError::Other(format!("{err:?}")))
}

// SRTP Profile Support Implementations

struct AppleCryptoSupportedAes128CmSha1_80;

impl std::fmt::Debug for AppleCryptoSupportedAes128CmSha1_80 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleCryptoSupportedAes128CmSha1_80")
            .finish()
    }
}

impl SupportedAes128CmSha1_80 for AppleCryptoSupportedAes128CmSha1_80 {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        Box::new(AppleCryptoAes128CmSha1_80Cipher { key })
    }
}

struct AppleCryptoSupportedAeadAes128Gcm;

impl std::fmt::Debug for AppleCryptoSupportedAeadAes128Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleCryptoSupportedAeadAes128Gcm").finish()
    }
}

impl SupportedAeadAes128Gcm for AppleCryptoSupportedAeadAes128Gcm {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        Box::new(AppleCryptoAeadAes128GcmCipher { key })
    }
}

struct AppleCryptoSupportedAeadAes256Gcm;

impl std::fmt::Debug for AppleCryptoSupportedAeadAes256Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleCryptoSupportedAeadAes256Gcm").finish()
    }
}

impl SupportedAeadAes256Gcm for AppleCryptoSupportedAeadAes256Gcm {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        Box::new(AppleCryptoAeadAes256GcmCipher { key })
    }
}

// SRTP Provider Implementation

pub(crate) struct AppleCryptoSrtpProvider;

impl std::fmt::Debug for AppleCryptoSrtpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleCryptoSrtpProvider").finish()
    }
}

impl SrtpProvider for AppleCryptoSrtpProvider {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &AppleCryptoSupportedAes128CmSha1_80
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &AppleCryptoSupportedAeadAes128Gcm
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &AppleCryptoSupportedAeadAes256Gcm
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        common_crypto::aes_ecb_round(key, input, output).unwrap();
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        common_crypto::aes_ecb_round(key, input, output).unwrap();
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
        let mut _count = 0;
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

    common_crypto::aes_ecb_round(
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
    fn test_srtp_aes_128_ecb_round_test_vec_1() {
        let key = hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c");
        let mut out = [0u8; 32];
        AppleCryptoSrtpProvider.srtp_aes_128_ecb_round(
            &key,
            &hex_to_vec("6bc1bee22e409f96e93d7e117393172a"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "3ad77bb40d7a3660a89ecaf32466ef97");
    }

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_2() {
        let key = hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c");
        let mut out = [0u8; 32];
        AppleCryptoSrtpProvider.srtp_aes_128_ecb_round(
            &key,
            &hex_to_vec("ae2d8a571e03ac9c9eb76fac45af8e51"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "f5d3d58503b9699de785895a96fdbaaf");
    }

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_3() {
        let key = hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c");
        let mut out = [0u8; 32];
        AppleCryptoSrtpProvider.srtp_aes_128_ecb_round(
            &key,
            &hex_to_vec("30c81c46a35ce411e5fbc1191a0a52ef"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "43b1cd7f598ece23881b00e3ed030688");
    }

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_4() {
        let key = hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c");
        let mut out = [0u8; 32];
        AppleCryptoSrtpProvider.srtp_aes_128_ecb_round(
            &key,
            &hex_to_vec("f69f2445df4f9b17ad2b417be66c3710"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "7b0c785e27e8ad3f8223207104725dd4");
    }

    #[test]
    fn test_srtp_aes_256_ecb_round_test_vec_1() {
        let key = hex_to_vec("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let mut out = [0u8; 32];
        AppleCryptoSrtpProvider.srtp_aes_256_ecb_round(
            &key,
            &hex_to_vec("6bc1bee22e409f96e93d7e117393172a"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "f3eed1bdb5d2a03c064b5a7e3db181f8");
    }

    #[test]
    fn test_srtp_aes_256_ecb_round_test_vec_2() {
        let key = hex_to_vec("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let mut out = [0u8; 32];
        AppleCryptoSrtpProvider.srtp_aes_256_ecb_round(
            &key,
            &hex_to_vec("ae2d8a571e03ac9c9eb76fac45af8e51"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "591ccb10d410ed26dc5ba74a31362870");
    }

    #[test]
    fn test_srtp_aes_256_ecb_round_test_vec_3() {
        let key = hex_to_vec("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let mut out = [0u8; 32];
        AppleCryptoSrtpProvider.srtp_aes_256_ecb_round(
            &key,
            &hex_to_vec("30c81c46a35ce411e5fbc1191a0a52ef"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "b6ed21b99ca6f4f9f153e7b1beafed1d");
    }

    #[test]
    fn test_srtp_aes_256_ecb_round_test_vec_4() {
        let key = hex_to_vec("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let mut out = [0u8; 32];
        AppleCryptoSrtpProvider.srtp_aes_256_ecb_round(
            &key,
            &hex_to_vec("f69f2445df4f9b17ad2b417be66c3710"),
            &mut out,
        );
        assert_eq!(slice_to_hex(&out[..16]), "23304b7a39f9f3ff067d8d8f9e24ecc7");
    }

    // AES-128-CTR Test Vectors from NIST SP 800-38A
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    // Section F.5.1

    #[test]
    fn test_aes_128_ctr_encrypt() {
        let key = hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_vec("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = hex_to_vec("6bc1bee22e409f96e93d7e117393172a");
        let expected = hex_to_vec("874d6191b620e3261bef6864990db6ce");

        let mut cipher = AppleCryptoAes128CmSha1_80Cipher {
            key: key.try_into().unwrap(),
        };
        let mut output = vec![0u8; plaintext.len()];
        cipher
            .encrypt(&iv.try_into().unwrap(), &plaintext, &mut output)
            .unwrap();

        assert_eq!(slice_to_hex(&output), slice_to_hex(&expected));
    }

    #[test]
    fn test_aes_128_ctr_decrypt() {
        let key = hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_vec("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ciphertext = hex_to_vec("874d6191b620e3261bef6864990db6ce");
        let expected = hex_to_vec("6bc1bee22e409f96e93d7e117393172a");

        let mut cipher = AppleCryptoAes128CmSha1_80Cipher {
            key: key.try_into().unwrap(),
        };
        let mut output = vec![0u8; ciphertext.len()];
        cipher
            .decrypt(&iv.try_into().unwrap(), &ciphertext, &mut output)
            .unwrap();

        assert_eq!(slice_to_hex(&output), slice_to_hex(&expected));
    }

    #[test]
    fn test_aes_128_ctr_multiple_blocks() {
        let key = hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_vec("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = hex_to_vec(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef",
        );
        let expected = hex_to_vec(
            "874d6191b620e3261bef6864990db6ce\
             9806f66b7970fdff8617187bb9fffdff\
             5ae4df3edbd5d35e5b4f09020db03eab",
        );

        let mut cipher = AppleCryptoAes128CmSha1_80Cipher {
            key: key.try_into().unwrap(),
        };
        let mut output = vec![0u8; plaintext.len()];
        cipher
            .encrypt(&iv.try_into().unwrap(), &plaintext, &mut output)
            .unwrap();

        assert_eq!(slice_to_hex(&output), slice_to_hex(&expected));
    }

    // AES-128-GCM Test Vectors from NIST SP 800-38D
    // https://csrc.nist.gov/publications/detail/sp/800-38d/final
    // Test Case 4

    #[test]
    fn test_aes_128_gcm_encrypt() {
        let key = hex_to_vec("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_vec("cafebabefacedbaddecaf888");
        let plaintext = hex_to_vec(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );
        let aad = hex_to_vec(
            "feedfacedeadbeeffeedfacedeadbeef\
             abaddad2",
        );
        let expected_ciphertext = hex_to_vec(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091",
        );
        let expected_tag = hex_to_vec("5bc94fbc3221a5db94fae95ae7121a47");

        let mut cipher = AppleCryptoAeadAes128GcmCipher {
            key: key.try_into().unwrap(),
        };
        let mut output = vec![0u8; plaintext.len() + 16];
        cipher
            .encrypt(&iv.try_into().unwrap(), &aad, &plaintext, &mut output)
            .unwrap();

        assert_eq!(
            slice_to_hex(&output[..plaintext.len()]),
            slice_to_hex(&expected_ciphertext)
        );
        assert_eq!(
            slice_to_hex(&output[plaintext.len()..]),
            slice_to_hex(&expected_tag)
        );
    }

    #[test]
    fn test_aes_128_gcm_decrypt() {
        let key = hex_to_vec("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_vec("cafebabefacedbaddecaf888");
        let ciphertext = hex_to_vec(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091",
        );
        let tag = hex_to_vec("5bc94fbc3221a5db94fae95ae7121a47");
        let aad = hex_to_vec(
            "feedfacedeadbeeffeedfacedeadbeef\
             abaddad2",
        );
        let expected_plaintext = hex_to_vec(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );

        let mut input = ciphertext.clone();
        input.extend_from_slice(&tag);

        let mut cipher = AppleCryptoAeadAes128GcmCipher {
            key: key.try_into().unwrap(),
        };
        let mut output = vec![0u8; ciphertext.len()];
        let len = cipher
            .decrypt(&iv.try_into().unwrap(), &[&aad], &input, &mut output)
            .unwrap();

        assert_eq!(len, expected_plaintext.len());
        assert_eq!(
            slice_to_hex(&output[..len]),
            slice_to_hex(&expected_plaintext)
        );
    }

    #[test]
    fn test_aes_128_gcm_decrypt_invalid_tag() {
        let key = hex_to_vec("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_vec("cafebabefacedbaddecaf888");
        let ciphertext = hex_to_vec(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091",
        );
        let bad_tag = hex_to_vec("0000000000000000000000000000000"); // Wrong tag
        let aad = hex_to_vec(
            "feedfacedeadbeeffeedfacedeadbeef\
             abaddad2",
        );

        let mut input = ciphertext.clone();
        input.extend_from_slice(&bad_tag);

        let mut cipher = AppleCryptoAeadAes128GcmCipher {
            key: key.try_into().unwrap(),
        };
        let mut output = vec![0u8; ciphertext.len()];
        let result = cipher.decrypt(&iv.try_into().unwrap(), &[&aad], &input, &mut output);

        assert!(result.is_err());
    }

    // AES-256-GCM Test Vectors from NIST SP 800-38D
    // Test Case 16

    #[test]
    fn test_aes_256_gcm_encrypt() {
        let key = hex_to_vec(
            "feffe9928665731c6d6a8f9467308308\
             feffe9928665731c6d6a8f9467308308",
        );
        let iv = hex_to_vec("cafebabefacedbaddecaf888");
        let plaintext = hex_to_vec(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );
        let aad = hex_to_vec(
            "feedfacedeadbeeffeedfacedeadbeef\
             abaddad2",
        );
        let expected_ciphertext = hex_to_vec(
            "522dc1f099567d07f47f37a32a84427d\
             643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838\
             c5f61e6393ba7a0abcc9f662",
        );
        let expected_tag = hex_to_vec("76fc6ece0f4e1768cddf8853bb2d551b");

        let mut cipher = AppleCryptoAeadAes256GcmCipher {
            key: key.try_into().unwrap(),
        };
        let mut output = vec![0u8; plaintext.len() + 16];
        cipher
            .encrypt(&iv.try_into().unwrap(), &aad, &plaintext, &mut output)
            .unwrap();

        assert_eq!(
            slice_to_hex(&output[..plaintext.len()]),
            slice_to_hex(&expected_ciphertext)
        );
        assert_eq!(
            slice_to_hex(&output[plaintext.len()..]),
            slice_to_hex(&expected_tag)
        );
    }

    #[test]
    fn test_aes_256_gcm_decrypt() {
        let key = hex_to_vec(
            "feffe9928665731c6d6a8f9467308308\
             feffe9928665731c6d6a8f9467308308",
        );
        let iv = hex_to_vec("cafebabefacedbaddecaf888");
        let ciphertext = hex_to_vec(
            "522dc1f099567d07f47f37a32a84427d\
             643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838\
             c5f61e6393ba7a0abcc9f662",
        );
        let tag = hex_to_vec("76fc6ece0f4e1768cddf8853bb2d551b");
        let aad = hex_to_vec(
            "feedfacedeadbeeffeedfacedeadbeef\
             abaddad2",
        );
        let expected_plaintext = hex_to_vec(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );

        let mut input = ciphertext.clone();
        input.extend_from_slice(&tag);

        let mut cipher = AppleCryptoAeadAes256GcmCipher {
            key: key.try_into().unwrap(),
        };
        let mut output = vec![0u8; ciphertext.len()];
        let len = cipher
            .decrypt(&iv.try_into().unwrap(), &[&aad], &input, &mut output)
            .unwrap();

        assert_eq!(len, expected_plaintext.len());
        assert_eq!(
            slice_to_hex(&output[..len]),
            slice_to_hex(&expected_plaintext)
        );
    }
}
