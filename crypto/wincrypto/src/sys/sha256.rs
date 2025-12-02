//! SHA-256 implementation using Windows CNG.

use crate::WinCryptoError;
use windows::core::Owned;
use windows::Win32::Security::Cryptography::BCryptHashData;
use windows::Win32::Security::Cryptography::BCRYPT_HASH_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_SHA256_ALG_HANDLE;
use windows::Win32::Security::Cryptography::{BCryptCreateHash, BCryptFinishHash};

/// Compute SHA-256 hash of the given data using Windows CNG.
pub fn sha256(data: &[u8]) -> Result<[u8; 32], WinCryptoError> {
    let mut hash = [0u8; 32];
    unsafe {
        let mut hash_handle = Owned::new(BCRYPT_HASH_HANDLE::default());

        WinCryptoError::from_ntstatus(BCryptCreateHash(
            BCRYPT_SHA256_ALG_HANDLE,
            &mut *hash_handle,
            None,
            None,
            0,
        ))?;

        WinCryptoError::from_ntstatus(BCryptHashData(*hash_handle, data, 0))?;

        WinCryptoError::from_ntstatus(BCryptFinishHash(*hash_handle, &mut hash, 0))?;
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
