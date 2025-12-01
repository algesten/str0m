//! TLS 1.2 PRF implementation using Apple CommonCrypto.

use dimpl::buffer::Buf;
use dimpl::crypto::{HashAlgorithm, PrfProvider};

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
                alg,                             // algorithm: SHA256 or SHA384
                secret.as_ptr() as *const _,     // key: PRF secret
                secret.len(),                    // keyLength: secret size
                label_seed.as_ptr() as *const _, // data: label || seed
                label_seed.len(),                // dataLength: label+seed size
                a.as_mut_ptr() as *mut _,        // macOut: A(1) output
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
                    alg,                                 // algorithm: SHA256 or SHA384
                    secret.as_ptr() as *const _,         // key: PRF secret
                    secret.len(),                        // keyLength: secret size
                    data.as_ptr() as *const _,           // data: A(i) || label || seed
                    data.len(),                          // dataLength: data size
                    output_block.as_mut_ptr() as *mut _, // macOut: P_hash output block
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
                        alg,                           // algorithm: SHA256 or SHA384
                        secret.as_ptr() as *const _,   // key: PRF secret
                        secret.len(),                  // keyLength: secret size
                        a.as_ptr() as *const _,        // data: A(i)
                        a.len(),                       // dataLength: hash output size
                        next_a.as_mut_ptr() as *mut _, // macOut: A(i+1) output
                    );
                }
                a = next_a;
            }
        }

        Ok(())
    }
}

pub(super) static PRF_PROVIDER: ApplePrfProvider = ApplePrfProvider;
