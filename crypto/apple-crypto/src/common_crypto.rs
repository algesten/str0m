//! CommonCrypto FFI bindings
//!
//! Most code should utilize CryptoKit APIs instead. However, for AES-ECB
//! we need to still rely on CommonCrypto.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use std::ffi::c_void;

use str0m_proto::crypto::CryptoError;

// CommonCrypto Type Definitions

type CCCryptorStatus = i32;
type CCOperation = u32;
type CCAlgorithm = u32;

// CommonCrypto Constants

// Status codes
const kCCSuccess: CCCryptorStatus = 0;

// Operations
const kCCEncrypt: CCOperation = 0;

// Algorithms
const kCCAlgorithmAES: CCAlgorithm = 0;

// Options
const kCCOptionECBMode: u32 = 2;

// CommonCrypto Function Declarations

extern "C" {
    // CCCrypt (one-shot encryption/decryption)

    fn CCCrypt(
        op: CCOperation,
        alg: CCAlgorithm,
        options: u32,
        key: *const c_void,
        keyLength: usize,
        iv: *const c_void,
        dataIn: *const c_void,
        dataInLength: usize,
        dataOut: *mut c_void,
        dataOutAvailable: usize,
        dataOutMoved: *mut usize,
    ) -> CCCryptorStatus;
}

/// Perform one round of AES-ECB encryption.
pub fn aes_ecb_round(key: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
    let mut data_out_moved: usize = 0;
    // SAFETY: CCCrypt is safe with valid key/input/output pointers and lengths
    let status = unsafe {
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
    };

    match status {
        kCCSuccess => Ok(()),
        status => Err(CryptoError::Other(format!(
            "AES-256-ECB encryption failed. Status: {status}"
        ))),
    }
}
