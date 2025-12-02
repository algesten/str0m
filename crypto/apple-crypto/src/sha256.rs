//! Apple CommonCrypto SHA-256 implementation.

use str0m_proto::crypto::Sha256Provider;

use crate::ffi::CC_SHA256;

/// Apple CommonCrypto-based SHA-256 provider.
#[derive(Debug)]
pub(crate) struct AppleCryptoSha256Provider;

impl Sha256Provider for AppleCryptoSha256Provider {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut result = [0u8; 32];
        // SAFETY: CC_SHA256 is safe with valid data pointer and length from slice,
        // and result buffer is properly sized for SHA256 (32 bytes)
        unsafe { CC_SHA256(data.as_ptr(), data.len() as u32, result.as_mut_ptr()) };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use str0m::crypto::Sha256Provider;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let hash = AppleCryptoSha256Provider.sha256(data);
        assert_eq!(hash.len(), 32);

        // Verify with known SHA-256 of "hello world"
        let expected = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_empty() {
        // SHA-256 of empty string
        let hash = AppleCryptoSha256Provider.sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256 of "abc" - NIST test vector
        let hash = AppleCryptoSha256Provider.sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }
}
