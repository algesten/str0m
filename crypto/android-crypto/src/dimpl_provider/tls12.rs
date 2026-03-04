//! TLS 1.2 PRF implementation using Android JNI crypto.

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, PrfProvider};

use crate::jni_crypto;

#[derive(Debug)]
pub(super) struct AndroidPrfProvider;

impl PrfProvider for AndroidPrfProvider {
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

        // Sized to the largest hash size we support (SHA-384 = 48 bytes)
        let mut hmac_a = [0u8; 48];

        // Build label + seed (this is our "seed" in P_hash terminology)
        scratch.clear();
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);
        let label_seed = scratch.as_ref();

        // Compute A(1) = HMAC(secret, label + seed)
        match hash {
            HashAlgorithm::SHA256 => {
                let result =
                    jni_crypto::hmac_sha256(secret, label_seed).map_err(|e| format!("{e:?}"))?;
                hmac_a[..32].copy_from_slice(&result);
            }
            HashAlgorithm::SHA384 => {
                let result =
                    jni_crypto::hmac_sha384(secret, label_seed).map_err(|e| format!("{e:?}"))?;
                hmac_a[..48].copy_from_slice(&result);
            }
            _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
        }

        // Build A(i) + label + seed
        scratch.clear();
        scratch.extend_from_slice(&hmac_a[..hash_len]);
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);
        let payload = scratch.as_mut();

        out.clear();
        while out.len() < output_len {
            // Compute HMAC(secret, A(i) + label + seed)
            let mut hmac_block = [0u8; 48];
            let hmac_block_length = match hash {
                HashAlgorithm::SHA256 => {
                    let result =
                        jni_crypto::hmac_sha256(secret, payload).map_err(|e| format!("{e:?}"))?;
                    hmac_block[..32].copy_from_slice(&result);
                    32
                }
                HashAlgorithm::SHA384 => {
                    let result =
                        jni_crypto::hmac_sha384(secret, payload).map_err(|e| format!("{e:?}"))?;
                    hmac_block[..48].copy_from_slice(&result);
                    48
                }
                _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
            };

            let remaining = output_len - out.len();
            let to_copy = std::cmp::min(remaining, hmac_block_length);
            out.extend_from_slice(&hmac_block[..to_copy]);

            if out.len() < output_len {
                // Calculate A(i+1) = HMAC(secret, A(i))
                // We take A(i) from the payload, since we need the src and dst to be different.
                match hash {
                    HashAlgorithm::SHA256 => {
                        let result = jni_crypto::hmac_sha256(secret, &payload[..hash_len])
                            .map_err(|e| format!("{e:?}"))?;
                        hmac_a[..32].copy_from_slice(&result);
                    }
                    HashAlgorithm::SHA384 => {
                        let result = jni_crypto::hmac_sha384(secret, &payload[..hash_len])
                            .map_err(|e| format!("{e:?}"))?;
                        hmac_a[..48].copy_from_slice(&result);
                    }
                    _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
                }
                // Copy it into the payload for the next round.
                payload[..hash_len].copy_from_slice(&hmac_a[..hash_len]);
            }
        }
        Ok(())
    }
}

pub(super) static PRF_PROVIDER: AndroidPrfProvider = AndroidPrfProvider;
