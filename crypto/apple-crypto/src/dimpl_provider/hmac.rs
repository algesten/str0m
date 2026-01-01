//! HMAC implementations using Apple CommonCrypto.

use dimpl::crypto::HmacProvider;

#[derive(Debug)]
pub(super) struct AppleHmacProvider;

impl HmacProvider for AppleHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        apple_cryptokit::hmac_sha256(key, data).map_err(|err| format!("{err:?}"))
    }
}

pub(super) static HMAC_PROVIDER: AppleHmacProvider = AppleHmacProvider;
