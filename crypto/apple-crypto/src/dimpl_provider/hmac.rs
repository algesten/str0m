//! HMAC implementations using Apple CommonCrypto.

use dimpl::crypto::HmacProvider;

#[derive(Debug)]
pub(super) struct AppleHmacProvider;

impl HmacProvider for AppleHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        apple_cryptokit::hmac_sha256(key, data).map_err(|err| format!("{err:?}"))
    }
}

pub(super) static HMAC_PROVIDER: AppleHmacProvider = AppleHmacProvider;

#[cfg(test)]
mod test {
    use super::*;

    // Test vectors from RFC 4231: Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256,
    // HMAC-SHA-384, and HMAC-SHA-512
    // https://tools.ietf.org/html/rfc4231

    fn hex_to_vec(hex: &str) -> Vec<u8> {
        let hex = hex.replace(" ", "").replace("\n", "");
        let mut v = Vec::new();
        for i in 0..hex.len() / 2 {
            let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            v.push(byte);
        }
        v
    }

    fn slice_to_hex(data: &[u8]) -> String {
        let mut s = String::new();
        for byte in data.iter() {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }

    // HMAC-SHA-256 Test Vectors from RFC 4231

    #[test]
    fn test_hmac_sha256_test_case_1() {
        let key = hex_to_vec("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

        let provider = AppleHmacProvider;
        let result = provider.hmac_sha256(&key, data).unwrap();
        assert_eq!(slice_to_hex(&result), expected);
    }

    #[test]
    fn test_hmac_sha256_test_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        let provider = AppleHmacProvider;
        let result = provider.hmac_sha256(key, data).unwrap();
        assert_eq!(slice_to_hex(&result), expected);
    }

    #[test]
    fn test_hmac_sha256_test_case_3() {
        let key = hex_to_vec("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let data = hex_to_vec(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
             dddddddddddddddddddddddddddddddddddd",
        );
        let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

        let provider = AppleHmacProvider;
        let result = provider.hmac_sha256(&key, &data).unwrap();
        assert_eq!(slice_to_hex(&result), expected);
    }

    #[test]
    fn test_hmac_sha256_test_case_4() {
        let key = hex_to_vec("0102030405060708090a0b0c0d0e0f10111213141516171819");
        let data = hex_to_vec(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
             cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        );
        let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

        let provider = AppleHmacProvider;
        let result = provider.hmac_sha256(&key, &data).unwrap();
        assert_eq!(slice_to_hex(&result), expected);
    }

    #[test]
    fn test_hmac_sha256_test_case_6() {
        // Test with a key larger than block size (> 64 bytes)
        // RFC 4231: key is 0xaa repeated 131 times
        let key = vec![0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

        let provider = AppleHmacProvider;
        let result = provider.hmac_sha256(&key, data).unwrap();
        assert_eq!(slice_to_hex(&result), expected);
    }

    #[test]
    fn test_hmac_sha256_test_case_7() {
        // Test with a key larger than block size and large data
        // RFC 4231: key is 0xaa repeated 131 times
        let key = vec![0xaa; 131];
        let data = b"This is a test using a larger than block-size key and a larger \
than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

        let provider = AppleHmacProvider;
        let result = provider.hmac_sha256(&key, data).unwrap();
        assert_eq!(slice_to_hex(&result), expected);
    }
}
