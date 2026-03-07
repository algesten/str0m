//! HMAC implementations using Windows CNG.

use dimpl::crypto::HmacProvider;

use windows::Win32::Security::Cryptography::BCRYPT_HASH_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_HMAC_SHA256_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCRYPT_HMAC_SHA384_ALG_HANDLE;
use windows::Win32::Security::Cryptography::BCryptCreateHash;
use windows::Win32::Security::Cryptography::BCryptFinishHash;
use windows::Win32::Security::Cryptography::BCryptHashData;
use windows::core::Owned;

use crate::WinCryptoError;

#[derive(Debug)]
pub(super) struct WinCngHmacProvider;

impl HmacProvider for WinCngHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        win_hmac_sha256(key, data).map_err(|e| format!("HMAC-SHA256 failed: {e}"))
    }
}

pub(super) static HMAC_PROVIDER: WinCngHmacProvider = WinCngHmacProvider;

pub(super) fn win_hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], WinCryptoError> {
    let mut hash = [0u8; 32];
    // SAFETY: Microsoft Learn documents `BCryptCreateHash`,
    // `BCryptHashData`, and `BCryptFinishHash` as borrowing the handle, key,
    // input, and output buffers only for the duration of each call; all of
    // them outlive this block.
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash
    unsafe {
        let mut hash_handle = Owned::new(BCRYPT_HASH_HANDLE::default());
        WinCryptoError::from_ntstatus(BCryptCreateHash(
            BCRYPT_HMAC_SHA256_ALG_HANDLE,
            &mut *hash_handle,
            None,
            Some(key),
            0,
        ))?;

        WinCryptoError::from_ntstatus(BCryptHashData(*hash_handle, data, 0))?;
        WinCryptoError::from_ntstatus(BCryptFinishHash(*hash_handle, &mut hash, 0))?;
    }
    Ok(hash)
}

pub(super) fn win_hmac_sha384(key: &[u8], data: &[u8]) -> Result<[u8; 48], WinCryptoError> {
    let mut hash = [0u8; 48];
    // SAFETY: Microsoft Learn documents `BCryptCreateHash`,
    // `BCryptHashData`, and `BCryptFinishHash` as borrowing the handle, key,
    // input, and output buffers only for the duration of each call; all of
    // them outlive this block.
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
    // Docs: https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinishhash
    unsafe {
        let mut hash_handle = Owned::new(BCRYPT_HASH_HANDLE::default());
        WinCryptoError::from_ntstatus(BCryptCreateHash(
            BCRYPT_HMAC_SHA384_ALG_HANDLE,
            &mut *hash_handle,
            None,
            Some(key),
            0,
        ))?;

        WinCryptoError::from_ntstatus(BCryptHashData(*hash_handle, data, 0))?;
        WinCryptoError::from_ntstatus(BCryptFinishHash(*hash_handle, &mut hash, 0))?;
    }
    Ok(hash)
}
