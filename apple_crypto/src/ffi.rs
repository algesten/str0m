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
pub(crate) type CCHmacAlgorithm = u32;
pub(crate) type CC_LONG = u32;

// CommonCrypto Constants

// Status codes
pub(crate) const kCCSuccess: CCCryptorStatus = 0;

// Operations
pub(crate) const kCCEncrypt: CCOperation = 0;
pub(crate) const kCCDecrypt: CCOperation = 1;

// Algorithms
pub(crate) const kCCAlgorithmAES: CCAlgorithm = 0;

// Modes
pub(crate) const kCCModeCTR: CCMode = 4;
pub(crate) const kCCModeGCM: CCMode = 11;

// Padding
pub(crate) const ccNoPadding: CCPadding = 0;

// Options
pub(crate) const kCCOptionECBMode: u32 = 2;

// HMAC Algorithms
pub(crate) const kCCHmacAlgSHA1: CCHmacAlgorithm = 0;
pub(crate) const kCCHmacAlgSHA256: CCHmacAlgorithm = 2;
pub(crate) const kCCHmacAlgSHA384: CCHmacAlgorithm = 3;

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

    // GCM-specific functions
    pub(crate) fn CCCryptorGCMAddIV(
        cryptorRef: CCCryptorRef,
        iv: *const c_void,
        ivLen: usize,
    ) -> CCCryptorStatus;

    pub(crate) fn CCCryptorGCMAddAAD(
        cryptorRef: CCCryptorRef,
        aad: *const c_void,
        aadLen: usize,
    ) -> CCCryptorStatus;

    pub(crate) fn CCCryptorGCMEncrypt(
        cryptorRef: CCCryptorRef,
        dataIn: *const c_void,
        dataInLength: usize,
        dataOut: *mut c_void,
    ) -> CCCryptorStatus;

    pub(crate) fn CCCryptorGCMDecrypt(
        cryptorRef: CCCryptorRef,
        dataIn: *const c_void,
        dataInLength: usize,
        dataOut: *mut c_void,
    ) -> CCCryptorStatus;

    pub(crate) fn CCCryptorGCMFinal(
        cryptorRef: CCCryptorRef,
        tag: *mut c_void,
        tagLength: *mut usize,
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

    // HMAC Functions (one-shot)

    pub(crate) fn CCHmac(
        algorithm: CCHmacAlgorithm,
        key: *const c_void,
        keyLength: usize,
        data: *const c_void,
        dataLength: usize,
        macOut: *mut c_void,
    );

    // HMAC Functions (streaming)

    pub(crate) fn CCHmacInit(
        ctx: *mut CCHmacContext,
        algorithm: CCHmacAlgorithm,
        key: *const c_void,
        keyLength: usize,
    );

    pub(crate) fn CCHmacUpdate(ctx: *mut CCHmacContext, data: *const c_void, dataLength: usize);

    pub(crate) fn CCHmacFinal(ctx: *mut CCHmacContext, macOut: *mut c_void);

    // SHA Hash Functions (one-shot)

    pub(crate) fn CC_SHA256(data: *const u8, len: u32, md: *mut u8) -> *mut u8;

    // SHA Hash Functions (streaming)

    pub(crate) fn CC_SHA256_Init(c: *mut CC_SHA256_CTX) -> i32;
    pub(crate) fn CC_SHA256_Update(c: *mut CC_SHA256_CTX, data: *const u8, len: CC_LONG) -> i32;
    pub(crate) fn CC_SHA256_Final(md: *mut u8, c: *mut CC_SHA256_CTX) -> i32;

    pub(crate) fn CC_SHA384_Init(c: *mut CC_SHA512_CTX) -> i32;
    pub(crate) fn CC_SHA384_Update(c: *mut CC_SHA512_CTX, data: *const u8, len: CC_LONG) -> i32;
    pub(crate) fn CC_SHA384_Final(md: *mut u8, c: *mut CC_SHA512_CTX) -> i32;
}

// SHA Context Structures

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CC_SHA256_CTX {
    pub(crate) count: [u32; 2],
    pub(crate) hash: [u32; 8],
    pub(crate) wbuf: [u32; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CC_SHA512_CTX {
    pub(crate) count: [u64; 2],
    pub(crate) hash: [u64; 8],
    pub(crate) wbuf: [u64; 16],
}

// HMAC Context Structure

/// HMAC context for streaming operations.
/// Size is CC_HMAC_CONTEXT_SIZE (96 u32 words = 384 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CCHmacContext {
    pub(crate) ctx: [u32; 96],
}

impl Default for CCHmacContext {
    fn default() -> Self {
        Self { ctx: [0u32; 96] }
    }
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

// Common Constants

/// GCM authentication tag length in bytes.
pub(crate) const GCM_TAG_LEN: usize = 16;
