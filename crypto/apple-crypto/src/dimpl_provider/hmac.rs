//! HMAC implementations using Apple CommonCrypto.

use dimpl::crypto::HmacProvider;

#[derive(Debug)]
pub(super) struct AppleHmacProvider;

impl HmacProvider for AppleHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        apple_cryptokit::hmac_sha256(key, data).map_err(|err| format!("{err:?}"))
    }

    fn hmac(
        &self,
        hash: dimpl::HashAlgorithm,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, String> {
        match hash {
            dimpl::HashAlgorithm::SHA256 => {
                let result =
                    apple_cryptokit::hmac_sha256(key, data).map_err(|err| format!("{err:?}"))?;
                let hmac_len = result.len();
                out[0..hmac_len].copy_from_slice(&result);
                if hmac_len <= out.len() {
                    out[0..hmac_len].copy_from_slice(&result);
                    Ok(hmac_len)
                } else {
                    Err(format!(
                        "Output buffer too small for SHA256. Needed: {hmac_len}, Was: {}",
                        out.len()
                    ))
                }
            }
            dimpl::HashAlgorithm::SHA384 => {
                let result =
                    apple_cryptokit::hmac_sha384(key, data).map_err(|err| format!("{err:?}"))?;
                let hmac_len = result.len();
                if hmac_len <= out.len() {
                    out[0..hmac_len].copy_from_slice(&result);
                    Ok(hmac_len)
                } else {
                    Err(format!(
                        "Output buffer too small for SHA384. Needed: {hmac_len}, Was: {}",
                        out.len()
                    ))
                }
            }
            _ => Err(format!("Unsupported HMAC Hash: {hash:?}")),
        }
    }
}

pub(super) static HMAC_PROVIDER: AppleHmacProvider = AppleHmacProvider;
