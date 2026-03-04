//! SHA1-HMAC implementation using Android JNI.

use str0m_proto::crypto::Sha1HmacProvider;

use crate::jni_crypto;

// SHA1 HMAC Provider Implementation

pub(crate) struct AndroidCryptoSha1HmacProvider;

impl std::fmt::Debug for AndroidCryptoSha1HmacProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCryptoSha1HmacProvider").finish()
    }
}

impl Sha1HmacProvider for AndroidCryptoSha1HmacProvider {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        static EMPTY: [u8; 0] = [];
        let payload = match payloads.len() {
            0 => &EMPTY,
            1 => payloads[0],
            _ => &payloads.concat(),
        };

        jni_crypto::hmac_sha1(key, payload).expect("HMAC-SHA1 computation failed")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use str0m_proto::crypto::Sha1HmacProvider;

    fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        AndroidCryptoSha1HmacProvider.sha1_hmac(key, payloads)
    }

    fn hash_to_hex(hash: [u8; 20]) -> String {
        hash.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // Test vectors from RFC 2202: https://www.rfc-editor.org/rfc/rfc2202

    #[test]
    fn test_rfc2202_test_case_1() {
        assert_eq!(
            hash_to_hex(sha1_hmac(&[0x0b; 20], &["Hi There".as_bytes()])),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }

    #[test]
    fn test_rfc2202_test_case_2() {
        assert_eq!(
            hash_to_hex(sha1_hmac(
                "Jefe".as_bytes(),
                &["what do ya want for nothing?".as_bytes()]
            )),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn test_rfc2202_test_case_3() {
        assert_eq!(
            hash_to_hex(sha1_hmac(&[0xaa; 20], &[[0xddu8; 50].as_slice()])),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
    }

    #[test]
    fn test_rfc2202_test_case_4() {
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
    fn test_rfc2202_test_case_5() {
        assert_eq!(
            hash_to_hex(sha1_hmac(&[0x0c; 20], &["Test With Truncation".as_bytes()])),
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
        );
    }

    #[test]
    fn test_rfc2202_test_case_6() {
        assert_eq!(
            hash_to_hex(sha1_hmac(
                &[0xaa; 80],
                &["Test Using Larger Than Block-Size Key - Hash Key First".as_bytes()]
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }

    #[test]
    fn test_rfc2202_test_case_7() {
        assert_eq!(
            hash_to_hex(sha1_hmac(
                &[0xaa; 80],
                &[
                    "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
                        .as_bytes()
                ]
            )),
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        );
    }

    #[test]
    fn test_multiple_payloads() {
        // Verify that multiple payloads produce the same result as concatenated
        let key = b"test_key";
        let payload1 = b"hello ";
        let payload2 = b"world";
        let combined = b"hello world";

        let result_separate = sha1_hmac(key, &[payload1, payload2]);
        let result_combined = sha1_hmac(key, &[combined]);

        assert_eq!(result_separate, result_combined);
    }
}
