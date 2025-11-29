//! TLS 1.2 PRF implementation using Apple CommonCrypto.

use str0m::crypto::dimpl_types::{Buf, HashAlgorithm, PrfProvider};

use crate::ffi::{kCCHmacAlgSHA256, kCCHmacAlgSHA384, CCHmac};

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
        let alg = match hash {
            HashAlgorithm::SHA256 => kCCHmacAlgSHA256,
            HashAlgorithm::SHA384 => kCCHmacAlgSHA384,
            _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
        };

        let hash_len = match hash {
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA384 => 48,
            _ => unreachable!(),
        };

        // Build label + seed
        scratch.clear();
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);
        let label_seed = scratch.to_vec();

        out.clear();

        // A(1) = HMAC(secret, A(0)) where A(0) = label_seed
        let mut a = vec![0u8; hash_len];
        unsafe {
            CCHmac(
                alg,
                secret.as_ptr() as *const _,
                secret.len(),
                label_seed.as_ptr() as *const _,
                label_seed.len(),
                a.as_mut_ptr() as *mut _,
            );
        }

        while out.len() < output_len {
            // HMAC(secret, A(i) + label_seed)
            let mut data = Vec::with_capacity(a.len() + label_seed.len());
            data.extend_from_slice(&a);
            data.extend_from_slice(&label_seed);

            let mut output_block = vec![0u8; hash_len];
            unsafe {
                CCHmac(
                    alg,
                    secret.as_ptr() as *const _,
                    secret.len(),
                    data.as_ptr() as *const _,
                    data.len(),
                    output_block.as_mut_ptr() as *mut _,
                );
            }

            let remaining = output_len - out.len();
            let to_copy = std::cmp::min(remaining, hash_len);
            out.extend_from_slice(&output_block[..to_copy]);

            if out.len() < output_len {
                // Calculate A(i+1) = HMAC(secret, A(i))
                let mut next_a = vec![0u8; hash_len];
                unsafe {
                    CCHmac(
                        alg,
                        secret.as_ptr() as *const _,
                        secret.len(),
                        a.as_ptr() as *const _,
                        a.len(),
                        next_a.as_mut_ptr() as *mut _,
                    );
                }
                a = next_a;
            }
        }

        Ok(())
    }
}

pub(super) static PRF_PROVIDER: ApplePrfProvider = ApplePrfProvider;
