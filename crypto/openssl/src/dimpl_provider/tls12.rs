//! TLS 1.2 PRF implementation using OpenSSL.

use dimpl::crypto::Buf;
use dimpl::crypto::{HashAlgorithm, PrfProvider};

use openssl::hash::MessageDigest;

#[derive(Debug)]
pub(super) struct OsslPrfProvider;

/// Compute HMAC using OpenSSL, writing the result to `out`.
fn hmac_compute(
    md: MessageDigest,
    key: &[u8],
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, String> {
    let result = super::hmac_openssl(md, key, data)?;
    let len = result.len();
    if len > out.len() {
        return Err(format!(
            "HMAC output ({len} bytes) exceeds buffer ({} bytes)",
            out.len()
        ));
    }
    out[..len].copy_from_slice(&result);
    Ok(len)
}

impl PrfProvider for OsslPrfProvider {
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
        let md = match hash {
            HashAlgorithm::SHA256 => MessageDigest::sha256(),
            HashAlgorithm::SHA384 => MessageDigest::sha384(),
            _ => return Err(format!("Unsupported hash algorithm for PRF: {hash:?}")),
        };

        let hash_len = hash.output_len();

        // Sized to the largest hash size we support (SHA-384 = 48 bytes)
        let mut hmac_a = [0u8; 48];

        // Build label + seed (this is our "seed" in P_hash terminology)
        scratch.clear();
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);
        let label_seed = scratch.as_ref();

        // Compute A(1) = HMAC(secret, label + seed)
        hmac_compute(md, secret, label_seed, &mut hmac_a)?;

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
            let hmac_block_length = hmac_compute(md, secret, payload, &mut hmac_block)?;

            let remaining = output_len - out.len();
            let to_copy = std::cmp::min(remaining, hmac_block_length);
            out.extend_from_slice(&hmac_block[..to_copy]);

            if out.len() < output_len {
                // Calculate A(i+1) = HMAC(secret, A(i))
                hmac_compute(md, secret, &payload[..hash_len], &mut hmac_a)?;
                // Copy it into the payload for the next round.
                payload[..hash_len].copy_from_slice(&hmac_a[..hash_len]);
            }
        }
        Ok(())
    }
}

pub(super) static PRF_PROVIDER: OsslPrfProvider = OsslPrfProvider;

#[cfg(test)]
mod tests {
    use super::*;

    /// Convert an ASCII hex array into a byte array at compile time.
    macro_rules! hex_as_bytes {
        ($input:expr) => {{
            const fn from_hex_char(c: u8) -> u8 {
                match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    b'A'..=b'F' => c - b'A' + 10,
                    _ => panic!("Invalid hex character"),
                }
            }

            const INPUT: &[u8] = $input;
            const LEN: usize = INPUT.len();
            const OUTPUT_LEN: usize = LEN / 2;

            const fn convert() -> [u8; OUTPUT_LEN] {
                assert!(LEN % 2 == 0, "Hex string length must be even");
                let mut out = [0u8; OUTPUT_LEN];
                let mut i = 0;
                while i < LEN {
                    out[i / 2] = (from_hex_char(INPUT[i]) << 4) | from_hex_char(INPUT[i + 1]);
                    i += 2;
                }
                out
            }

            convert()
        }};
    }

    // Test vector from https://github.com/xomexh/TLS-PRF
    #[test]
    fn prf_tls12_sha256() {
        let mut output = Buf::new();
        let mut scratch = Buf::new();
        let provider = OsslPrfProvider;
        provider
            .prf_tls12(
                &hex_as_bytes!(b"9bbe436ba940f017b17652849a71db35"),
                "test label",
                &hex_as_bytes!(b"a0ba9f936cda311827a6f796ffd5198c"),
                &mut output,
                100,
                &mut scratch,
                HashAlgorithm::SHA256,
            )
            .unwrap();
        assert_eq!(
            output.as_ref(),
            &hex_as_bytes!(
                b"e3f229ba727be17b8d122620557cd453c2aab21d\
                  07c3d495329b52d4e61edb5a6b301791e90d35c9\
                  c9a46b4e14baf9af0fa022f7077def17abfd3797\
                  c0564bab4fbc91666e9def9b97fce34f796789ba\
                  a48082d122ee42c5a72e5a5110fff70187347b66"
            )
        );
    }
}
