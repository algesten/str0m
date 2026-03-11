//! SHA-256 implementation using Windows CNG.

use crate::WinCryptoError;
use windows::Win32::Security::Cryptography::BCRYPT_SHA256_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCryptHash;

/// Compute SHA-256 hash of the given data using Windows CNG.
pub fn sha256(data: &[u8]) -> Result<[u8; 32], WinCryptoError> {
    let mut hash = [0u8; 32];
    unsafe {
        WinCryptoError::from_ntstatus(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, data, &mut hash))?;
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let hash = sha256(data).unwrap();
        assert_eq!(hash.len(), 32);

        // Verify with known SHA-256 of "hello world"
        let expected = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];
        assert_eq!(hash, expected);
    }
}
