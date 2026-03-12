//! HMAC implementations using Apple CommonCrypto.

use dimpl::HashAlgorithm;
use str0m_proto::crypto::dimpl::DimplCommonHmacProvider;
use str0m_proto::impl_hmac_providers;

#[derive(Debug, Default)]
pub(super) struct AppleHmacProvider;

impl DimplCommonHmacProvider for AppleHmacProvider {
    /// Compute HMAC for the given hash algorithm, writing the result to `out`.
    /// Returns the number of bytes written.
    fn hmac(
        &self,
        hash: HashAlgorithm,
        key: &[u8],
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize, String> {
        match hash {
            HashAlgorithm::SHA256 => {
                apple_cryptokit::authentication::hmac_sha256_to(key, data, output)
            }
            HashAlgorithm::SHA384 => {
                apple_cryptokit::authentication::hmac_sha384_to(key, data, output)
            }
            HashAlgorithm::SHA512 => {
                apple_cryptokit::authentication::hmac_sha512_to(key, data, output)
            }
            _ => return Err(format!("Unsupported hash algorithm: {hash:?}")),
        }
        .map_err(|err| format!("CryptoKitError: {err:?}"))
    }
}

impl_hmac_providers!(AppleHmacProvider);

pub(super) static HMAC_PROVIDER: AppleHmacProvider = AppleHmacProvider;
