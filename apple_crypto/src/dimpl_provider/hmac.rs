//! HMAC implementations using Apple CommonCrypto.

use dimpl::crypto::HmacProvider;

use crate::ffi::{CCHmac, kCCHmacAlgSHA256};

#[derive(Debug)]
pub(super) struct AppleHmacProvider;

impl HmacProvider for AppleHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        let mut out = [0u8; 32];
        // SAFETY: CCHmac is safe with valid key, data pointers and lengths from slices,
        // and out buffer is properly sized for SHA256 (32 bytes)
        unsafe {
            CCHmac(
                kCCHmacAlgSHA256,           // algorithm: HMAC-SHA256
                key.as_ptr() as *const _,   // key: HMAC key
                key.len(),                  // keyLength: key size
                data.as_ptr() as *const _,  // data: message to authenticate
                data.len(),                 // dataLength: message size
                out.as_mut_ptr() as *mut _, // macOut: 32-byte output
            );
        }
        Ok(out)
    }
}

pub(super) static HMAC_PROVIDER: AppleHmacProvider = AppleHmacProvider;
