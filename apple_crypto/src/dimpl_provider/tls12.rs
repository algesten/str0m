//! TLS 1.2 PRF implementation using Apple CommonCrypto.

use dimpl::buffer::Buf;
use dimpl::crypto::{HashAlgorithm, PrfProvider};

use crate::ffi::{kCCHmacAlgSHA256, kCCHmacAlgSHA384};
use crate::ffi::{CCHmacContext, CCHmacFinal, CCHmacInit, CCHmacUpdate};

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
        // Use streaming HMAC to avoid Vec allocation
        let mut a = [0u8; 48]; // Large enough for SHA384 (48 bytes)
        let mut ctx = CCHmacContext::default();

        // SAFETY: CCHmacInit/Update/Final are safe with valid context, key,
        // data pointers and lengths from slices.
        unsafe {
            CCHmacInit(&mut ctx, alg, secret.as_ptr() as *const _, secret.len());
            CCHmacUpdate(&mut ctx, label_seed.as_ptr() as *const _, label_seed.len());
            CCHmacFinal(&mut ctx, a.as_mut_ptr() as *mut _);
        }

        // Reusable output block buffer (stack allocated)
        let mut output_block = [0u8; 48]; // Large enough for SHA384

        while out.len() < output_len {
            // HMAC(secret, A(i) + label_seed) using streaming API
            // This avoids allocating a Vec to concatenate A(i) and label_seed
            unsafe {
                CCHmacInit(&mut ctx, alg, secret.as_ptr() as *const _, secret.len());
                CCHmacUpdate(&mut ctx, a.as_ptr() as *const _, hash_len);
                CCHmacUpdate(&mut ctx, label_seed.as_ptr() as *const _, label_seed.len());
                CCHmacFinal(&mut ctx, output_block.as_mut_ptr() as *mut _);
            }

            let remaining = output_len - out.len();
            let to_copy = std::cmp::min(remaining, hash_len);
            out.extend_from_slice(&output_block[..to_copy]);

            if out.len() < output_len {
                // Calculate A(i+1) = HMAC(secret, A(i))
                // Use a temporary buffer to avoid aliasing issues
                let mut next_a = [0u8; 48];
                unsafe {
                    CCHmacInit(&mut ctx, alg, secret.as_ptr() as *const _, secret.len());
                    CCHmacUpdate(&mut ctx, a.as_ptr() as *const _, hash_len);
                    CCHmacFinal(&mut ctx, next_a.as_mut_ptr() as *mut _);
                }
                a = next_a;
            }
        }

        Ok(())
    }
}

pub(super) static PRF_PROVIDER: ApplePrfProvider = ApplePrfProvider;
