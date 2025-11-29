//! CommonCrypto FFI bindings shared across Apple crypto modules.
//!
//! This module centralizes all CommonCrypto function declarations and constants
//! to avoid duplication across cipher_suite.rs, srtp.rs, hash.rs, hmac.rs, etc.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use std::ffi::c_void;

// ============================================================================
// CommonCrypto Type Definitions
// ============================================================================

pub type CCCryptorStatus = i32;
pub type CCOperation = u32;
pub type CCAlgorithm = u32;
pub type CCMode = u32;
pub type CCPadding = u32;
pub type CCCryptorRef = *mut c_void;
pub type CCHmacAlgorithm = u32;
pub type CC_LONG = u32;

// ============================================================================
// CommonCrypto Constants
// ============================================================================

// Status codes
pub const kCCSuccess: CCCryptorStatus = 0;

// Operations
pub const kCCEncrypt: CCOperation = 0;
pub const kCCDecrypt: CCOperation = 1;

// Algorithms
pub const kCCAlgorithmAES: CCAlgorithm = 0;

// Modes
pub const kCCModeCTR: CCMode = 4;
pub const kCCModeGCM: CCMode = 11;

// Padding
pub const ccNoPadding: CCPadding = 0;

// Options
pub const kCCOptionECBMode: u32 = 2;

// HMAC Algorithms
pub const kCCHmacAlgSHA1: CCHmacAlgorithm = 0;
pub const kCCHmacAlgSHA256: CCHmacAlgorithm = 2;
pub const kCCHmacAlgSHA384: CCHmacAlgorithm = 3;

// ============================================================================
// CommonCrypto Function Declarations
// ============================================================================

extern "C" {
    // ========================================================================
    // CCCryptor Functions (for AES-GCM, AES-CTR, etc.)
    // ========================================================================

    pub fn CCCryptorCreateWithMode(
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

    pub fn CCCryptorRelease(cryptorRef: CCCryptorRef) -> CCCryptorStatus;

    pub fn CCCryptorUpdate(
        cryptorRef: CCCryptorRef,
        dataIn: *const c_void,
        dataInLength: usize,
        dataOut: *mut c_void,
        dataOutAvailable: usize,
        dataOutMoved: *mut usize,
    ) -> CCCryptorStatus;

    // GCM-specific functions
    pub fn CCCryptorGCMAddIV(
        cryptorRef: CCCryptorRef,
        iv: *const c_void,
        ivLen: usize,
    ) -> CCCryptorStatus;

    pub fn CCCryptorGCMAddAAD(
        cryptorRef: CCCryptorRef,
        aad: *const c_void,
        aadLen: usize,
    ) -> CCCryptorStatus;

    pub fn CCCryptorGCMEncrypt(
        cryptorRef: CCCryptorRef,
        dataIn: *const c_void,
        dataInLength: usize,
        dataOut: *mut c_void,
    ) -> CCCryptorStatus;

    pub fn CCCryptorGCMDecrypt(
        cryptorRef: CCCryptorRef,
        dataIn: *const c_void,
        dataInLength: usize,
        dataOut: *mut c_void,
    ) -> CCCryptorStatus;

    pub fn CCCryptorGCMFinal(
        cryptorRef: CCCryptorRef,
        tag: *mut c_void,
        tagLength: *mut usize,
    ) -> CCCryptorStatus;

    // ========================================================================
    // CCCrypt (one-shot encryption/decryption)
    // ========================================================================

    pub fn CCCrypt(
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

    // ========================================================================
    // HMAC Functions
    // ========================================================================

    pub fn CCHmac(
        algorithm: CCHmacAlgorithm,
        key: *const c_void,
        keyLength: usize,
        data: *const c_void,
        dataLength: usize,
        macOut: *mut c_void,
    );

    // ========================================================================
    // SHA Hash Functions (one-shot)
    // ========================================================================

    pub fn CC_SHA256(data: *const u8, len: u32, md: *mut u8) -> *mut u8;

    // ========================================================================
    // SHA Hash Functions (streaming)
    // ========================================================================

    pub fn CC_SHA256_Init(c: *mut CC_SHA256_CTX) -> i32;
    pub fn CC_SHA256_Update(c: *mut CC_SHA256_CTX, data: *const u8, len: CC_LONG) -> i32;
    pub fn CC_SHA256_Final(md: *mut u8, c: *mut CC_SHA256_CTX) -> i32;

    pub fn CC_SHA384_Init(c: *mut CC_SHA512_CTX) -> i32;
    pub fn CC_SHA384_Update(c: *mut CC_SHA512_CTX, data: *const u8, len: CC_LONG) -> i32;
    pub fn CC_SHA384_Final(md: *mut u8, c: *mut CC_SHA512_CTX) -> i32;
}

// ============================================================================
// SHA Context Structures
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CC_SHA256_CTX {
    pub count: [u32; 2],
    pub hash: [u32; 8],
    pub wbuf: [u32; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CC_SHA512_CTX {
    pub count: [u64; 2],
    pub hash: [u64; 8],
    pub wbuf: [u64; 16],
}

// ============================================================================
// RAII Guard for CCCryptorRef
// ============================================================================

/// RAII guard that automatically releases a CCCryptorRef when dropped.
pub struct CryptorGuard(pub CCCryptorRef);

impl Drop for CryptorGuard {
    fn drop(&mut self) {
        unsafe {
            CCCryptorRelease(self.0);
        }
    }
}

// ============================================================================
// Common Constants
// ============================================================================

/// GCM authentication tag length in bytes.
pub const GCM_TAG_LEN: usize = 16;
