//! CommonCrypto FFI bindings shared across Apple crypto modules.
//!
//! This module centralizes all CommonCrypto function declarations and constants
//! to avoid duplication across cipher_suite.rs, srtp.rs, hash.rs, hmac.rs, etc.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use std::ffi::c_void;

// CommonCrypto Type Definitions

pub(crate) type CCCryptorStatus = i32;
pub(crate) type CCOperation = u32;
pub(crate) type CCAlgorithm = u32;
pub(crate) type CCMode = u32;
pub(crate) type CCPadding = u32;
pub(crate) type CCCryptorRef = *mut c_void;

// CommonCrypto Constants

// Status codes
pub(crate) const kCCSuccess: CCCryptorStatus = 0;

// Operations
pub(crate) const kCCEncrypt: CCOperation = 0;

// Algorithms
pub(crate) const kCCAlgorithmAES: CCAlgorithm = 0;

// Modes
pub(crate) const kCCModeCTR: CCMode = 4;

// Padding
pub(crate) const ccNoPadding: CCPadding = 0;

// Options
pub(crate) const kCCOptionECBMode: u32 = 2;

// CommonCrypto Function Declarations

extern "C" {
    // CCCryptor Functions (for AES-GCM, AES-CTR, etc.)

    pub(crate) fn CCCryptorCreateWithMode(
        op: CCOperation,
        mode: CCMode,
        alg: CCAlgorithm,
        padding: CCPadding,
        iv: *const c_void,
        key: *const c_void,
        keyLength: usize,
        tweak: *const c_void,
        tweakLength: usize,
        numRounds: i32,
        options: u32,
        cryptorRef: *mut CCCryptorRef,
    ) -> CCCryptorStatus;

    pub(crate) fn CCCryptorRelease(cryptorRef: CCCryptorRef) -> CCCryptorStatus;

    pub(crate) fn CCCryptorUpdate(
        cryptorRef: CCCryptorRef,
        dataIn: *const c_void,
        dataInLength: usize,
        dataOut: *mut c_void,
        dataOutAvailable: usize,
        dataOutMoved: *mut usize,
    ) -> CCCryptorStatus;

    // CCCrypt (one-shot encryption/decryption)

    pub(crate) fn CCCrypt(
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

// RAII Guard for CCCryptorRef

/// RAII guard that automatically releases a CCCryptorRef when dropped.
pub(crate) struct CryptorGuard(pub(crate) CCCryptorRef);

impl Drop for CryptorGuard {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid CCCryptorRef that was created by CCCryptorCreateWithMode
        unsafe { CCCryptorRelease(self.0) };
    }
}
