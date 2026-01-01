//! SRTP cipher implementations using Apple CommonCrypto.
use str0m_proto::crypto::SupportedAeadAes128Gcm;
use str0m_proto::crypto::{AeadAes128Gcm, AeadAes128GcmCipher, AeadAes256Gcm, AeadAes256GcmCipher};
use str0m_proto::crypto::{Aes128CmSha1_80Cipher, CryptoError, SrtpProvider};
use str0m_proto::crypto::{SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};

use crate::ffi::ccNoPadding;
use crate::ffi::kCCAlgorithmAES;
use crate::ffi::kCCEncrypt;
use crate::ffi::kCCModeCTR;
use crate::ffi::kCCOptionECBMode;
use crate::ffi::kCCSuccess;
use crate::ffi::CCCrypt;
use crate::ffi::CCCryptorCreateWithMode;
use crate::ffi::CCCryptorRef;
use crate::ffi::CCCryptorStatus;
use crate::ffi::CCCryptorUpdate;
use crate::ffi::CryptorGuard;

// CTR Helper Functions

/// Create a CTR cryptor and perform encryption/decryption.
fn ctr_crypt(
    key: &[u8],
    iv: &[u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    let mut cryptor: CCCryptorRef = std::ptr::null_mut();
    // SAFETY: CCCryptorCreateWithMode is safe with valid key/iv pointers and lengths
    let status = unsafe {
        CCCryptorCreateWithMode(
            kCCEncrypt,               // operation: encrypt (CTR is symmetric)
            kCCModeCTR,               // mode: Counter Mode
            kCCAlgorithmAES,          // algorithm: AES
            ccNoPadding,              // padding: none (stream cipher)
            iv.as_ptr() as *const _,  // iv: 16-byte counter block
            key.as_ptr() as *const _, // key: encryption key
            key.len(),                // keyLength: 16 bytes for AES-128
            std::ptr::null(),         // tweak: not used for CTR
            0,                        // tweakLength: not used
            0,                        // numRounds: 0 = default
            0,                        // options: none
            &mut cryptor,             // cryptorRef: output handle
        )
    };
    if status != kCCSuccess {
        return Err(CryptoError::Other(format!(
            "CCCryptorCreateWithMode failed: {status}"
        )));
    }
    let _guard = CryptorGuard(cryptor);

    let mut data_out_moved: usize = 0;
    // SAFETY: cryptor is valid, input/output pointers and lengths are from valid slices
    let status = unsafe {
        CCCryptorUpdate(
            cryptor,                       // cryptorRef: active cryptor
            input.as_ptr() as *const _,    // dataIn: input data
            input.len(),                   // dataInLength: input size
            output.as_mut_ptr() as *mut _, // dataOut: output buffer
            output.len(),                  // dataOutAvailable: output capacity
            &mut data_out_moved,           // dataOutMoved: bytes written
        )
    };
    if status != kCCSuccess {
        return Err(CryptoError::Other(format!(
            "AES-CTR encrypt failed: {status}"
        )));
    }

    Ok(())
}

/// Perform one round of AES-ECB encryption.
fn aes_ecb_round(key: &[u8], input: &[u8], output: &mut [u8]) -> CCCryptorStatus {
    let mut data_out_moved: usize = 0;
    // SAFETY: CCCrypt is safe with valid key/input/output pointers and lengths
    unsafe {
        CCCrypt(
            kCCEncrypt,                    // operation: encrypt
            kCCAlgorithmAES,               // algorithm: AES
            kCCOptionECBMode,              // options: ECB mode (no chaining)
            key.as_ptr() as *const _,      // key: encryption key
            key.len(),                     // keyLength: 16 or 32 bytes
            std::ptr::null(),              // iv: not used for ECB
            input.as_ptr() as *const _,    // dataIn: input block
            input.len(),                   // dataInLength: must be block-aligned
            output.as_mut_ptr() as *mut _, // dataOut: output buffer
            output.len(),                  // dataOutAvailable: output capacity
            &mut data_out_moved,           // dataOutMoved: bytes written
        )
    }
}

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
        ctr_crypt(&self.key, iv, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        // AES-CTR mode is symmetric, so we can use the same operation
        self.encrypt(iv, input, output)
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
        assert!(
            aad.len() >= 12,
            "Associated data length MUST be at least 12 octets"
        );

        output.copy_from_slice(
            apple_cryptokit::aes_gcm_encrypt_with_aad(&self.key, iv, input, aad)
                .map_err(|err| CryptoError::Other(format!("{err:?}")))?
                .as_slice(),
        );

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

        static EMPTY: [u8; 0] = [];
        let aad = match aads.len() {
            0 => &EMPTY,
            1 => aads[0],
            _ => &aads.concat(),
        };

        let output_vec = apple_cryptokit::aes_gcm_decrypt_with_aad(&self.key, iv, input, aad)
            .map_err(|err| CryptoError::Other(format!("{err:?}")))?;
        output.copy_from_slice(output_vec.as_slice());

        Ok(output_vec.len())
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
        assert!(
            aad.len() >= 12,
            "Associated data length MUST be at least 12 octets"
        );

        output.copy_from_slice(
            apple_cryptokit::aes_gcm_encrypt_with_aad(&self.key, iv, input, aad)
                .map_err(|err| CryptoError::Other(format!("{err:?}")))?
                .as_slice(),
        );

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

        static EMPTY: [u8; 0] = [];
        let aad = match aads.len() {
            0 => &EMPTY,
            1 => aads[0],
            _ => &aads.concat(),
        };

        let output_vec = apple_cryptokit::aes_gcm_decrypt_with_aad(&self.key, iv, input, aad)
            .map_err(|err| CryptoError::Other(format!("{err:?}")))?;
        output.copy_from_slice(output_vec.as_slice());

        Ok(output_vec.len())
    }
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
        let status = aes_ecb_round(key, input, output);
        assert_eq!(status, kCCSuccess, "AES-128-ECB encryption failed");
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        let status = aes_ecb_round(key, input, output);
        assert_eq!(status, kCCSuccess, "AES-256-ECB encryption failed");
    }
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
}
