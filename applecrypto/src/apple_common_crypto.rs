/// Declares constants and function defintions that comes from the System for
/// Apple's CommonCrypto.
use std::ffi::c_void;

// CommonCrypto constants
pub const K_CC_HMAC_ALG_SHA1: u32 = 0;

pub const K_CC_ALGORITHM_AES: u32 = 0;
pub const K_CC_OPTION_ECB_MODE: u32 = 1;
pub const K_CC_MODE_GCM: u32 = 11;
pub const K_CC_ENCRYPT: u32 = 0;
pub const K_CC_DECRYPT: u32 = 1;

// SHA constants
pub const CC_SHA256_DIGEST_LENGTH: usize = 32;

// AES key sizes
pub const K_CC_AES_KEY_SIZE_128: usize = 16;
pub const K_CC_AES_KEY_SIZE_192: usize = 24;
pub const K_CC_AES_KEY_SIZE_256: usize = 32;

// CommonCrypto function bindings
#[link(name = "System")]
extern "C" {
    pub fn CCHmac(
        algorithm: u32,
        key: *const c_void,
        key_length: usize,
        data: *const c_void,
        data_length: usize,
        mac_out: *mut c_void,
    );

    pub fn CC_SHA256(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;

    pub fn CCCryptorCreate(
        op: u32,
        alg: u32,
        options: u32,
        key: *const u8,
        key_length: usize,
        iv: *const u8,
        cryptor_ref: *mut *mut c_void,
    ) -> i32;

    pub fn CCCryptorCreateWithMode(
        op: u32,
        mode: u32,
        alg: u32,
        padding: u32,
        iv: *const u8,
        key: *const u8,
        key_length: usize,
        tweak: *const u8,
        tweak_length: usize,
        num_rounds: i32,
        mode_options: u32,
        cryptor_ref: *mut *mut c_void,
    ) -> i32;

    pub fn CCCryptorUpdate(
        cryptor_ref: *mut c_void,
        data_in: *const u8,
        data_in_length: usize,
        data_out: *mut u8,
        data_out_available: usize,
        data_out_moved: *mut usize,
    ) -> i32;

    pub fn CCCryptorFinal(
        cryptor_ref: *mut c_void,
        data_out: *mut u8,
        data_out_available: usize,
        data_out_moved: *mut usize,
    ) -> i32;

    pub fn CCCryptorRelease(cryptor_ref: *mut c_void) -> i32;

    pub fn CCCryptorGCMAddIV(cryptor_ref: *mut c_void, iv: *const u8, iv_len: usize) -> i32;

    pub fn CCCryptorGCMAddAAD(cryptor_ref: *mut c_void, aad: *const u8, aad_len: usize) -> i32;

    pub fn CCCryptorGCMEncrypt(
        cryptor_ref: *mut c_void,
        data_in: *const u8,
        data_in_length: usize,
        data_out: *mut u8,
    ) -> i32;

    pub fn CCCryptorGCMDecrypt(
        cryptor_ref: *mut c_void,
        data_in: *const u8,
        data_in_length: usize,
        data_out: *mut u8,
    ) -> i32;

    pub fn CCCryptorGCMFinal(cryptor_ref: *mut c_void, tag: *mut u8, tag_len: *mut usize) -> i32;
}
