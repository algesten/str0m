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

        // Build label + seed
        scratch.clear();
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);
        let label_seed = scratch.to_vec();

        out.clear();

        let hmac_seed_length = match hash {
            HashAlgorithm::SHA256 => apple_cryptokit::authentication::hmac_sha256_to(
                secret,
                &label_seed,
                hmac_seed.as_mut_slice(),
            ),
            HashAlgorithm::SHA384 => apple_cryptokit::authentication::hmac_sha384_to(
                secret,
                &label_seed,
                hmac_seed.as_mut_slice(),
            ),
            _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
        }
        .map_err(|err| format!("{err:?}"))?;

        while out.len() < output_len {
            // HMAC(secret, A(i) + label_seed)
            let payload = [&hmac_seed[..hmac_seed_length], label_seed.as_slice()].concat();
            let mut hmac_block = [0; apple_cryptokit::authentication::HMAC_SHA384_OUTPUT_SIZE];

            let hmac_block_length = match hash {
                HashAlgorithm::SHA256 => apple_cryptokit::authentication::hmac_sha256_to(
                    secret,
                    &payload,
                    hmac_block.as_mut_slice(),
                ),
                HashAlgorithm::SHA384 => apple_cryptokit::authentication::hmac_sha384_to(
                    secret,
                    &payload,
                    hmac_block.as_mut_slice(),
                ),
                _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
            }
            .map_err(|err| format!("{err:?}"))?;

            let remaining = output_len - out.len();
            let to_copy = std::cmp::min(remaining, hmac_block_length);
            out.extend_from_slice(&hmac_block[..to_copy]);

            if out.len() < output_len {
                let mut tmp_hmac_seed =
                    [0; apple_cryptokit::authentication::HMAC_SHA384_OUTPUT_SIZE];

                // Calculate A(i+1) = HMAC(secret, A(i))
                match hash {
                    HashAlgorithm::SHA256 => apple_cryptokit::authentication::hmac_sha256_to(
                        secret,
                        &hmac_seed,
                        tmp_hmac_seed.as_mut_slice(),
                    ),
                    HashAlgorithm::SHA384 => apple_cryptokit::authentication::hmac_sha384_to(
                        secret,
                        &hmac_seed,
                        tmp_hmac_seed.as_mut_slice(),
                    ),
                    _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
                }
                .map_err(|err| format!("{err:?}"))?;
                hmac_seed.copy_from_slice(&tmp_hmac_seed);
            }
        }

        Ok(())
    }
}

pub(super) static PRF_PROVIDER: ApplePrfProvider = ApplePrfProvider;
