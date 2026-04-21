//! HMAC implementations using OpenSSL.

use dimpl::crypto::HmacProvider;

use openssl::hash::MessageDigest;

#[derive(Debug)]
pub(super) struct OsslHmacProvider;

impl HmacProvider for OsslHmacProvider {
    fn hmac(
        &self,
        hash: dimpl::HashAlgorithm,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, String> {
        let pkey = openssl::pkey::PKey::hmac(key).map_err(|e| format!("{e}"))?;
        let mut signer = match hash {
            dimpl::HashAlgorithm::SHA256 => {
                openssl::sign::Signer::new(MessageDigest::sha256(), &pkey)
                    .map_err(|e| format!("{e}"))
            }
            dimpl::HashAlgorithm::SHA384 => {
                openssl::sign::Signer::new(MessageDigest::sha384(), &pkey)
                    .map_err(|e| format!("{e}"))
            }
            _ => Err(format!("Unsupported HMAC Hash: {hash:?}")),
        }?;
        signer.update(data).map_err(|e| format!("{e}"))?;
        signer.sign(out).map_err(|e| format!("{e}"))
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
