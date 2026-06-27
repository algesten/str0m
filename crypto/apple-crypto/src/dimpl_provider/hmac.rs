//! HMAC implementations using Apple CommonCrypto.

use dimpl::crypto::HmacProvider;
use dimpl::{CryptoError, CryptoOperation};

#[derive(Debug)]
pub(super) struct AppleHmacProvider;

impl HmacProvider for AppleHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
        apple_cryptokit::hmac_sha256(key, data)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::ComputeHmac))
    }

    fn hmac(
        &self,
        hash: dimpl::HashAlgorithm,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        match hash {
            dimpl::HashAlgorithm::SHA256 => {
                let result = apple_cryptokit::hmac_sha256(key, data)
                    .map_err(|_| CryptoError::OperationFailed(CryptoOperation::ComputeHmac))?;
                let hmac_len = result.len();
                if hmac_len <= out.len() {
                    out[0..hmac_len].copy_from_slice(&result);
                    Ok(hmac_len)
                } else {
                    Err(CryptoError::OperationFailed(CryptoOperation::ComputeHmac))
                }
            }
            dimpl::HashAlgorithm::SHA384 => {
                let result = apple_cryptokit::hmac_sha384(key, data)
                    .map_err(|_| CryptoError::OperationFailed(CryptoOperation::ComputeHmac))?;
                let hmac_len = result.len();
                if hmac_len <= out.len() {
                    out[0..hmac_len].copy_from_slice(&result);
                    Ok(hmac_len)
                } else {
                    Err(CryptoError::OperationFailed(CryptoOperation::ComputeHmac))
                }
            }
            _ => Err(CryptoError::UnsupportedHmacHash(hash)),
        }
    }
}

pub(super) static HMAC_PROVIDER: AppleHmacProvider = AppleHmacProvider;
