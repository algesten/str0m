//! HMAC implementations using OpenSSL.

use dimpl::crypto::HmacProvider;

use openssl::hash::MessageDigest;

#[derive(Debug)]
pub(super) struct OsslHmacProvider;

impl HmacProvider for OsslHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        let result = super::hmac_openssl(MessageDigest::sha256(), key, data)?;
        result
            .try_into()
            .map_err(|v: Vec<u8>| format!("HMAC-SHA256 produced {} bytes, expected 32", v.len()))
    }
}

pub(super) static HMAC_PROVIDER: OsslHmacProvider = OsslHmacProvider;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dimpl_provider::test_utils::{hex_to_vec, to_hex};

    // RFC 4231 Test Case 1
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = hex_to_vec("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let result = OsslHmacProvider.hmac_sha256(&key, data).unwrap();
        assert_eq!(
            to_hex(&result),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    // RFC 4231 Test Case 2
    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let result = OsslHmacProvider
            .hmac_sha256(b"Jefe", b"what do ya want for nothing?")
            .unwrap();
        assert_eq!(
            to_hex(&result),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    // RFC 4231 Test Case 3
    #[test]
    fn hmac_sha256_rfc4231_case3() {
        let key = hex_to_vec("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let data = hex_to_vec(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
             dddddddddddddddddddddddddddddddddddd",
        );
        let result = OsslHmacProvider.hmac_sha256(&key, &data).unwrap();
        assert_eq!(
            to_hex(&result),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }
}
