//! TLS 1.2 PRF implementation using Apple CommonCrypto.

use dimpl::buffer::Buf;
use dimpl::crypto::{HashAlgorithm, PrfProvider};

#[derive(Debug)]
pub(super) struct ApplePrfProvider;

impl PrfProvider for ApplePrfProvider {
    fn prf_tls12(
        &self,
        secret: &[u8],
        label: &str,
        seed: &[u8],
        out: &mut Buf,
        output_len: usize,
        scratch: &mut Buf,
        hash: HashAlgorithm,
    ) -> Result<(), String> {
        // Build label + seed
        scratch.clear();
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);
        let label_seed = scratch.to_vec();

        out.clear();

        let mut hmac_seed = match hash {
            HashAlgorithm::SHA256 => {
                apple_cryptokit::hmac_sha256(secret, &label_seed).map(Vec::from)
            }
            HashAlgorithm::SHA384 => {
                apple_cryptokit::hmac_sha384(secret, &label_seed).map(Vec::from)
            }
            _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
        }
        .map_err(|err| format!("{err:?}"))?;

        while out.len() < output_len {
            // HMAC(secret, A(i) + label_seed)
            let payload = [hmac_seed.as_slice(), label_seed.as_slice()].concat();
            let hmac_block = match hash {
                HashAlgorithm::SHA256 => {
                    apple_cryptokit::hmac_sha256(secret, &payload).map(Vec::from)
                }
                HashAlgorithm::SHA384 => {
                    apple_cryptokit::hmac_sha384(secret, &payload).map(Vec::from)
                }
                _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
            }
            .map_err(|err| format!("{err:?}"))?;

            let remaining = output_len - out.len();
            let to_copy = std::cmp::min(remaining, hmac_block.len());
            out.extend_from_slice(&hmac_block[..to_copy]);

            if out.len() < output_len {
                // Calculate A(i+1) = HMAC(secret, A(i))
                // Use a temporary buffer to avoid aliasing issues

                hmac_seed = match hash {
                    HashAlgorithm::SHA256 => {
                        apple_cryptokit::hmac_sha256(secret, &hmac_seed).map(Vec::from)
                    }
                    HashAlgorithm::SHA384 => {
                        apple_cryptokit::hmac_sha384(secret, &hmac_seed).map(Vec::from)
                    }
                    _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
                }
                .map_err(|err| format!("{err:?}"))?;
            }
        }

        Ok(())
    }
}

pub(super) static PRF_PROVIDER: ApplePrfProvider = ApplePrfProvider;
