//! HMAC implementations using Apple CryptoKit.

use dimpl::crypto::HmacProvider;
use dimpl::{CryptoError, CryptoOperation};

#[derive(Debug)]
pub(super) struct AppleHmacProvider;

impl HmacProvider for AppleHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
        Ok(crate::cryptokit::hmac(key, &[data]))
    }

    fn hmac(
        &self,
        hash: dimpl::HashAlgorithm,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        match hash {
            dimpl::HashAlgorithm::SHA256 => crate::cryptokit::hmac_into::<32>(key, &[data], out),
            dimpl::HashAlgorithm::SHA384 => crate::cryptokit::hmac_into::<48>(key, &[data], out),
            _ => return Err(CryptoError::UnsupportedHmacHash(hash)),
        }
        .map_err(|_| CryptoError::OperationFailed(CryptoOperation::ComputeHmac))
    }
}

pub(super) static HMAC_PROVIDER: AppleHmacProvider = AppleHmacProvider;
