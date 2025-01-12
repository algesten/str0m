use super::WinCryptoError;
use std::ptr::addr_of;
use windows::{
    core::Owned,
    Win32::Security::Cryptography::{
        BCryptDecrypt, BCryptEncrypt, BCryptGenerateSymmetricKey, BCRYPT_AES_ECB_ALG_HANDLE,
        BCRYPT_AES_GCM_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, BCRYPT_BLOCK_PADDING, BCRYPT_FLAGS,
        BCRYPT_KEY_HANDLE,
    },
};

const MAX_BUFFER_SIZE: usize = 2048;
const AEAD_AES_GCM_TAG_LEN: usize = 16;

/// SRTP Key wraps the CNG key, so that it can be destroyed when it is
/// no longer used. Because it is tracked, it is important that StrpKey
/// does NOT implement Clone/Copy, otherwise we could destroy the key
/// too early. It is also why access to the key handle should remain
/// hidden.
pub struct SrtpKey(Owned<BCRYPT_KEY_HANDLE>);
// SAFETY: BCRYPT_KEY_HANDLEs are safe to send between threads.
unsafe impl Send for SrtpKey {}
// SAFETY: BCRYPT_KEY_HANDLEs are safe to send between threads.
unsafe impl Sync for SrtpKey {}

impl SrtpKey {
    /// Creates a key from the given data for operating AES in Counter (CTR/CM) mode.
    pub fn create_aes_ctr_key(key: &[u8]) -> Result<Self, WinCryptoError> {
        // CTR mode is build on top of ECB mode, so we use the same key.
        Self::create_aes_ecb_key(key)
    }

    /// Creates a key from the given data for operating AES in ECB mode.
    pub fn create_aes_ecb_key(key: &[u8]) -> Result<Self, WinCryptoError> {
        // SAFETY: The key and key_handle will exist before and after this call.
        unsafe {
            let mut key_handle = Owned::new(BCRYPT_KEY_HANDLE::default());
            WinCryptoError::from_ntstatus(BCryptGenerateSymmetricKey(
                BCRYPT_AES_ECB_ALG_HANDLE,
                &mut *key_handle,
                None,
                &key,
                0,
            ))?;
            Ok(Self(key_handle))
        }
    }

    /// Creates a key from the given data for operating AES in GCM mode.
    pub fn create_aes_gcm_key(key: &[u8]) -> Result<Self, WinCryptoError> {
        // SAFETY: The key and key_handle will exist before and after this call.
        unsafe {
            let mut key_handle = Owned::new(BCRYPT_KEY_HANDLE::default());
            WinCryptoError::from_ntstatus(BCryptGenerateSymmetricKey(
                BCRYPT_AES_GCM_ALG_HANDLE,
                &mut *key_handle,
                None,
                &key,
                0,
            ))?;
            Ok(Self(key_handle))
        }
    }
}

/// Run the given input through the AES-128-ECB using the given AES ECB key.
pub fn srtp_aes_128_ecb_round(
    key: &SrtpKey,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, WinCryptoError> {
    let mut count = 0;
    // SAFETY: The Windows API accepts references, so normal borrow checker
    // behaviors work.
    unsafe {
        WinCryptoError::from_ntstatus(BCryptEncrypt(
            *key.0,
            Some(input),
            None,
            None,
            Some(output),
            &mut count,
            BCRYPT_BLOCK_PADDING,
        ))?;
    }
    Ok(count as usize)
}

/// Run the given input through the AES-128-CM using the given AES CTR/CM key.
pub fn srtp_aes_128_cm(
    key: &SrtpKey,
    iv: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, WinCryptoError> {
    // First, we'll make a copy of the IV with a countered as many times as
    // needed into a new countered_iv.
    let mut iv = iv.to_vec();
    let mut countered_iv = [0u8; MAX_BUFFER_SIZE];
    let mut offset = 0;
    while offset <= input.len() {
        let mut _count = 0;
        let start = offset;
        let end = offset + 16;
        countered_iv[start..end].copy_from_slice(&iv);
        offset += 16;
        for idx in 0..16 {
            let n = iv[15 - idx];
            if n == 0xff {
                iv[15 - idx] = 0;
            } else {
                iv[15 - idx] += 1;
                break;
            }
        }
    }

    let mut count = 0;
    // SAFETY: The Windows API accepts references, so normal borrow checker
    // behaviors work. The spare reference used to pass a mutable and immutable
    // reference into the BCryptEncypt method relies on `countered_iv` which exists
    // beyond the unsafe block.
    unsafe {
        // Now, we'll encrypt the countered IV. CNG can do this in-place, so we'll need
        // a separate reference to the slice, but fool the borrow-checker, otherwise it
        // won't like us passing the immutable and mutable reference to BCryptEncrypt.
        let encrypted_countered_iv =
            std::slice::from_raw_parts_mut(countered_iv.as_mut_ptr(), countered_iv.len());
        WinCryptoError::from_ntstatus(BCryptEncrypt(
            *key.0,
            Some(&countered_iv[..offset]),
            None,
            None,
            Some(&mut encrypted_countered_iv[..offset]),
            &mut count,
            BCRYPT_FLAGS(0),
        ))?;
    }

    // XOR the intermediate_output with the input
    for i in 0..input.len() {
        output[i] = input[i] ^ countered_iv[i];
    }

    Ok(input.len() as usize)
}

/// Run the given plain_text through the AES-128-GCM alg with the given key and receive the
/// cipher_text which will include the auth tag.
pub fn srtp_aead_aes_128_gcm_encrypt(
    key: &SrtpKey,
    iv: &[u8],
    additional_auth_data: &[u8],
    plain_text: &[u8],
    cipher_text: &mut [u8],
) -> Result<usize, WinCryptoError> {
    if cipher_text.len() < plain_text.len() {
        return Err(WinCryptoError(
            "Cipher Text is to small to include TAG".to_string(),
        ));
    }

    assert!(
        additional_auth_data.len() >= 12,
        "Associated data length MUST be at least 12 octets"
    );

    let auth_cipher_mode_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        pbAuthData: additional_auth_data.as_ptr() as *mut u8,
        cbAuthData: additional_auth_data.len() as u32,
        dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        pbTag: cipher_text[plain_text.len()..].as_ptr() as *mut u8,
        cbTag: AEAD_AES_GCM_TAG_LEN as u32,
        pbNonce: iv.as_ptr() as *mut u8,
        cbNonce: iv.len() as u32,
        ..Default::default()
    };

    let mut count = 0;
    // SAFETY: The Windows API accepts references, so normal borrow checker
    // behaviors work for those. The `auth_cipher_mode_info` however, contains
    // pointers. It is important that the data pointed to there (`additional_auth_data`,
    // `cipher_text` and `iv`) exists for the duration of the unsafe block.
    unsafe {
        WinCryptoError::from_ntstatus(BCryptEncrypt(
            *key.0,
            Some(plain_text),
            Some(addr_of!(auth_cipher_mode_info) as *const std::ffi::c_void),
            None,
            Some(cipher_text),
            &mut count,
            BCRYPT_FLAGS(0),
        ))?;
    }
    Ok(count as usize)
}

/// Run the given tagged cipher_text through the AES-128-GCM alg with the given key and
/// receive the decrypted plain_text.
pub fn srtp_aead_aes_128_gcm_decrypt(
    key: &SrtpKey,
    iv: &[u8],
    additional_auth_data: &[&[u8]],
    cipher_text: &[u8],
    plain_text: &mut [u8],
) -> Result<usize, WinCryptoError> {
    if cipher_text.len() < AEAD_AES_GCM_TAG_LEN {
        return Err(WinCryptoError(
            "Cipher Text too short to include tag".to_string(),
        ));
    }
    let (cipher_text, tag) = cipher_text.split_at(cipher_text.len() - AEAD_AES_GCM_TAG_LEN);

    // If don't have exactly one auth_data, we need to flatten it. This will
    // hold our reference to the data.
    let flattened_auth_data = if additional_auth_data.len() != 1 {
        Some(additional_auth_data.concat())
    } else {
        None
    };
    let additional_auth_data = flattened_auth_data
        .as_ref()
        .map_or(additional_auth_data[0], |f| f.as_slice());

    let auth_cipher_mode_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        pbAuthData: additional_auth_data.as_ptr() as *mut u8,
        cbAuthData: additional_auth_data.len() as u32,
        dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        pbTag: tag.as_ptr() as *mut u8,
        cbTag: tag.len() as u32,
        pbNonce: iv.as_ptr() as *mut u8,
        cbNonce: iv.len() as u32,
        ..Default::default()
    };

    let mut count = 0;
    // SAFETY: The Windows API accepts references, so normal borrow checker
    // behaviors work for those. The `auth_cipher_mode_info` however, contains
    // pointers. It is important that the data pointed to there (`additional_auth_data`,
    // `cipher_text` and `iv`) exists for the duration of the unsafe block.
    unsafe {
        WinCryptoError::from_ntstatus(BCryptDecrypt(
            *key.0,
            Some(cipher_text),
            Some(addr_of!(auth_cipher_mode_info) as *const std::ffi::c_void),
            None,
            Some(plain_text),
            &mut count,
            BCRYPT_FLAGS(0),
        ))?;
    }
    Ok(count as usize)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_1() {
        let key =
            SrtpKey::create_aes_ecb_key(&hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        let mut out = [0u8; 32];
        srtp_aes_128_ecb_round(
            &key,
            &hex_to_vec("6bc1bee22e409f96e93d7e117393172a"),
            &mut out,
        )
        .unwrap();
        assert_eq!(slice_to_hex(&out[..16]), "3ad77bb40d7a3660a89ecaf32466ef97");
    }

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_2() {
        let key =
            SrtpKey::create_aes_ecb_key(&hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        let mut out = [0u8; 32];
        srtp_aes_128_ecb_round(
            &key,
            &hex_to_vec("ae2d8a571e03ac9c9eb76fac45af8e51"),
            &mut out,
        )
        .unwrap();
        assert_eq!(slice_to_hex(&out[..16]), "f5d3d58503b9699de785895a96fdbaaf");
    }

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_3() {
        let key =
            SrtpKey::create_aes_ecb_key(&hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        let mut out = [0u8; 32];
        srtp_aes_128_ecb_round(
            &key,
            &hex_to_vec("30c81c46a35ce411e5fbc1191a0a52ef"),
            &mut out,
        )
        .unwrap();
        assert_eq!(slice_to_hex(&out[..16]), "43b1cd7f598ece23881b00e3ed030688");
    }

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_4() {
        let key =
            SrtpKey::create_aes_ecb_key(&hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        let mut out = [0u8; 32];
        srtp_aes_128_ecb_round(
            &key,
            &hex_to_vec("f69f2445df4f9b17ad2b417be66c3710"),
            &mut out,
        )
        .unwrap();
        assert_eq!(slice_to_hex(&out[..16]), "7b0c785e27e8ad3f8223207104725dd4");
    }

    fn slice_to_hex(hash: &[u8]) -> String {
        let mut s = String::new();
        for byte in hash.iter() {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }

    fn hex_to_vec(hex: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..hex.len() / 2 {
            let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            v.push(byte);
        }
        v
    }
}
