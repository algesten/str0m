//! TLS 1.2 PRF implementation using Windows CNG HMAC.

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, PrfProvider};

#[derive(Debug)]
pub(super) struct WinCngPrfProvider;

impl PrfProvider for WinCngPrfProvider {
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
        let hash_len = match hash {
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA384 => 48,
            _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
        };

        // Build label + seed
        scratch.clear();
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);
        let label_seed = scratch.as_ref().to_vec();

        // Compute A(1) = HMAC(secret, label + seed)
        let mut a = hmac_vec(hash, secret, &label_seed)?;

        out.clear();
        while out.len() < output_len {
            // Compute HMAC(secret, A(i) + label + seed)
            let mut payload = Vec::with_capacity(a.len() + label_seed.len());
            payload.extend_from_slice(&a);
            payload.extend_from_slice(&label_seed);

            let hmac_block = hmac_vec(hash, secret, &payload)?;

            let remaining = output_len - out.len();
            let to_copy = std::cmp::min(remaining, hash_len);
            out.extend_from_slice(&hmac_block[..to_copy]);

            if out.len() < output_len {
                // A(i+1) = HMAC(secret, A(i))
                a = hmac_vec(hash, secret, &a)?;
            }
        }
        Ok(())
    }
}

fn hmac_vec(hash: HashAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    match hash {
        HashAlgorithm::SHA256 => super::hmac::win_hmac_sha256(key, data)
            .map(|h| h.to_vec())
            .map_err(|e| format!("{e}")),
        HashAlgorithm::SHA384 => super::hmac::win_hmac_sha384(key, data)
            .map(|h| h.to_vec())
            .map_err(|e| format!("{e}")),
        _ => Err(format!("Unsupported hash: {hash:?}")),
    }
}

pub(super) static PRF_PROVIDER: WinCngPrfProvider = WinCngPrfProvider;
