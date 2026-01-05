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
        // Sized to the largest hash size we support.
        let mut hmac_seed = [0; apple_cryptokit::authentication::HMAC_SHA384_OUTPUT_SIZE];
        let hmac_seed_length = match hash {
            HashAlgorithm::SHA256 => apple_cryptokit::authentication::HMAC_SHA256_OUTPUT_SIZE,
            HashAlgorithm::SHA384 => apple_cryptokit::authentication::HMAC_SHA384_OUTPUT_SIZE,
            _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
        };

        // Build label + seed
        scratch.clear();
        scratch.extend_from_slice(&hmac_seed[..hmac_seed_length]);
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);
        let payload = scratch.as_mut();

        match hash {
            HashAlgorithm::SHA256 => apple_cryptokit::authentication::hmac_sha256_to(
                secret,
                &payload[hmac_seed_length..],
                hmac_seed.as_mut_slice(),
            ),
            HashAlgorithm::SHA384 => apple_cryptokit::authentication::hmac_sha384_to(
                secret,
                &payload[hmac_seed_length..],
                hmac_seed.as_mut_slice(),
            ),
            _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
        }
        .map_err(|err| format!("{err:?}"))?;

        out.clear();
        while out.len() < output_len {
            // HMAC(secret, A(i) + label_seed)

            // Update the payload with the last computed hash.
            payload[..hmac_seed_length].copy_from_slice(&hmac_seed[..hmac_seed_length]);

            let mut hmac_block = [0; apple_cryptokit::authentication::HMAC_SHA384_OUTPUT_SIZE];
            let hmac_block_length = match hash {
                HashAlgorithm::SHA256 => apple_cryptokit::authentication::hmac_sha256_to(
                    secret,
                    payload,
                    hmac_block.as_mut_slice(),
                ),
                HashAlgorithm::SHA384 => apple_cryptokit::authentication::hmac_sha384_to(
                    secret,
                    payload,
                    hmac_block.as_mut_slice(),
                ),
                _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
            }
            .map_err(|err| format!("{err:?}"))?;

            let remaining = output_len - out.len();
            let to_copy = std::cmp::min(remaining, hmac_block_length);
            out.extend_from_slice(&hmac_block[..to_copy]);
            if out.len() < output_len {
                // Calculate A(i+1) = HMAC(secret, A(i))
                match hash {
                    HashAlgorithm::SHA256 => apple_cryptokit::authentication::hmac_sha256_to(
                        secret,
                        payload,
                        hmac_seed.as_mut_slice(),
                    ),
                    HashAlgorithm::SHA384 => apple_cryptokit::authentication::hmac_sha384_to(
                        secret,
                        payload,
                        hmac_seed.as_mut_slice(),
                    ),
                    _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
                }
                .map_err(|err| format!("{err:?}"))?;
            }
        }
        Ok(())
    }
}

pub(super) static PRF_PROVIDER: ApplePrfProvider = ApplePrfProvider;
