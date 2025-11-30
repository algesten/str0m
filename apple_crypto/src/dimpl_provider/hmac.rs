//! HMAC implementations using Apple CommonCrypto.

use dimpl::crypto::HmacProvider;

use crate::ffi::{kCCHmacAlgSHA256, CCHmac};

#[derive(Debug)]
pub(super) struct AppleHmacProvider;

impl HmacProvider for AppleHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        let mut out = [0u8; 32];
        unsafe {
            CCHmac(
                kCCHmacAlgSHA256,
                key.as_ptr() as *const _,
                key.len(),
                data.as_ptr() as *const _,
                data.len(),
                out.as_mut_ptr() as *mut _,
            );
        }
        Ok(out)
    }
}

pub(super) static HMAC_PROVIDER: AppleHmacProvider = AppleHmacProvider;
