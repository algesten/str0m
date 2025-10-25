use std::ffi::c_void;

use super::apple_common_crypto::*;
use super::AppleCryptoError;

const CC_SHA1_DIGEST_LENGTH: usize = 20;

/// Computes HMAC-SHA1 using Apple's CommonCrypto framework.
///
/// This implementation uses the system-provided CCHmac function from
/// Apple's CommonCrypto library, which provides optimized cryptographic
/// operations on macOS and iOS platforms.
///
/// # Arguments
///
/// * `key` - The secret key for HMAC computation
/// * `payloads` - Array of byte slices to be hashed (concatenated)
///
/// # Returns
///
/// Returns a Result containing the 20-byte SHA-1 HMAC digest, or an
/// AppleCryptoError if the operation fails.
pub fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> Result<[u8; 20], AppleCryptoError> {
    // Concatenate all payloads into a single buffer
    let total_len: usize = payloads.iter().map(|p| p.len()).sum();
    let mut data = Vec::with_capacity(total_len);
    for payload in payloads {
        data.extend_from_slice(payload);
    }

    let mut result = [0u8; CC_SHA1_DIGEST_LENGTH];

    unsafe {
        CCHmac(
            K_CC_HMAC_ALG_SHA1,
            key.as_ptr() as *const c_void,
            key.len(),
            data.as_ptr() as *const c_void,
            data.len(),
            result.as_mut_ptr() as *mut c_void,
        );
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rfc2022_test_case_1() {
        assert_eq!(
            hash_to_hex(sha1_hmac(&[0x0b; 20], &["Hi There".as_bytes()])),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }

    #[test]
    fn test_rfc2022_test_case_2() {
        assert_eq!(
            hash_to_hex(sha1_hmac(
                &"Jefe".as_bytes(),
                &["what do ya want for nothing?".as_bytes()]
            )),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn test_rfc2022_test_case_3() {
        assert_eq!(
            hash_to_hex(sha1_hmac(&[0xaa; 20], &[[0xddu8; 50].as_slice()])),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
    }

    #[test]
    fn test_rfc2022_test_case_4() {
        assert_eq!(
            hash_to_hex(sha1_hmac(
                &[
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                    23, 24, 25
                ],
                &[[0xcdu8; 50].as_slice()]
            )),
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
        );
    }

    #[test]
    fn test_rfc2022_test_case_5() {
        assert_eq!(
            hash_to_hex(sha1_hmac(&[0x0c; 20], &["Test With Truncation".as_bytes()])),
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
        );
    }

    #[test]
    fn test_rfc2022_test_case_6() {
        assert_eq!(
            hash_to_hex(sha1_hmac(
                &[0xaa; 80],
                &["Test Using Larger Than Block-Size Key - Hash Key First".as_bytes()]
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }

    #[test]
    fn test_rfc2022_test_case_7() {
        assert_eq!(
            hash_to_hex(sha1_hmac(
                &[0xaa; 80],
                &[
                    "Test Using Larger Than Block-Size Key and Larger ".as_bytes(),
                    "Than One Block-Size Data".as_bytes()
                ]
            )),
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        );
    }

    fn hash_to_hex(hash: Result<[u8; 20], AppleCryptoError>) -> String {
        let hash = hash.unwrap();
        let mut s = String::new();
        for byte in hash.iter() {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }
}
