use std::ptr::addr_of;

use super::WinCryptoError;
use windows::Win32::Security::Cryptography::{
    BCryptDecrypt, BCryptDestroyKey, BCryptEncrypt, BCryptGenerateSymmetricKey,
    BCRYPT_AES_ECB_ALG_HANDLE, BCRYPT_AES_GCM_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, BCRYPT_BLOCK_PADDING, BCRYPT_FLAGS,
    BCRYPT_KEY_HANDLE,
};

const MAX_BUFFER_SIZE: usize = 2048;
const AEAD_AES_GCM_TAG_LEN: usize = 16;

pub struct WinCryptoSrtpKey(BCRYPT_KEY_HANDLE);
unsafe impl Send for WinCryptoSrtpKey {}
unsafe impl Sync for WinCryptoSrtpKey {}

impl WinCryptoSrtpKey {
    pub fn create_aes_ctr_key(key: &[u8]) -> Result<Self, WinCryptoError> {
        // CTR mode is build on top of ECB mode, so we use the same key.
        Self::create_aes_ecb_key(key)
    }

    pub fn create_aes_ecb_key(key: &[u8]) -> Result<Self, WinCryptoError> {
        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        unsafe {
            WinCryptoError::from_ntstatus(BCryptGenerateSymmetricKey(
                BCRYPT_AES_ECB_ALG_HANDLE,
                &mut key_handle,
                None,
                &key,
                0,
            ))?;
        }
        Ok(Self(key_handle))
    }

    pub fn create_aes_gcm_key(key: &[u8]) -> Result<Self, WinCryptoError> {
        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        unsafe {
            WinCryptoError::from_ntstatus(BCryptGenerateSymmetricKey(
                BCRYPT_AES_GCM_ALG_HANDLE,
                &mut key_handle,
                None,
                &key,
                0,
            ))?;
        }
        Ok(Self(key_handle))
    }
}

impl Drop for WinCryptoSrtpKey {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = WinCryptoError::from_ntstatus(BCryptDestroyKey(self.0)) {
                error!("Failed to destory crypto key: {}", e);
            }
        }
    }
}

pub fn wincrypto_srtp_aes_128_ecb_round(
    key: &WinCryptoSrtpKey,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, WinCryptoError> {
    unsafe {
        // Run AES
        let mut count = 0;
        WinCryptoError::from_ntstatus(BCryptEncrypt(
            key.0,
            Some(input),
            None,
            None,
            Some(output),
            &mut count,
            BCRYPT_BLOCK_PADDING,
        ))?;
        Ok(count as usize)
    }
}

pub fn wincrypto_srtp_aes_128_cm(
    key: &WinCryptoSrtpKey,
    iv: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, WinCryptoError> {
    unsafe {
        // First, we'll make a copy of the IV with a countered as many times as needed into a new
        // countered_iv.
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

        // Now, we'll encrypt the countered IV. CNG can do this in-place, so we'll need a separate
        // reference to the slice, but fool the borrow-checker, otherwise it won't like us passing
        // the immutable and mutable reference to BCryptEncrypt.
        let encrypted_countered_iv =
            std::slice::from_raw_parts_mut(countered_iv.as_mut_ptr(), countered_iv.len());
        let mut _count = 0;
        WinCryptoError::from_ntstatus(BCryptEncrypt(
            key.0,
            Some(&countered_iv[..offset]),
            None,
            None,
            Some(&mut encrypted_countered_iv[..offset]),
            &mut _count,
            BCRYPT_FLAGS(0),
        ))?;

        // XOR the intermediate_output with the input
        for i in 0..input.len() {
            output[i] = input[i] ^ encrypted_countered_iv[i];
        }
        Ok(input.len())
    }
}

pub fn wincrypto_srtp_aead_aes_128_gcm_encrypt(
    key: &WinCryptoSrtpKey,
    iv: &[u8],
    additional_auth_data: &[u8],
    plain_text: &[u8],
    cipher_text: &mut [u8],
) -> Result<usize, WinCryptoError> {
    unsafe {
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
        WinCryptoError::from_ntstatus(BCryptEncrypt(
            key.0,
            Some(plain_text),
            Some(addr_of!(auth_cipher_mode_info) as *const std::ffi::c_void),
            None,
            Some(cipher_text),
            &mut count,
            BCRYPT_FLAGS(0),
        ))?;

        Ok(count as usize)
    }
}

pub fn wincrypto_srtp_aead_aes_128_gcm_decrypt(
    key: &WinCryptoSrtpKey,
    iv: &[u8],
    additional_auth_data: &[&[u8]],
    cipher_text: &[u8],
    plain_text: &mut [u8],
) -> Result<usize, WinCryptoError> {
    unsafe {
        if cipher_text.len() < AEAD_AES_GCM_TAG_LEN {
            return Err(WinCryptoError(
                "Cipher Text too short to include tag".to_string(),
            ));
        }
        let (cipher_text, tag) = cipher_text.split_at(cipher_text.len() - AEAD_AES_GCM_TAG_LEN);

        // TODO(efer): Optimize this, we shouldn't need a vec, only need it when
        // we have multiple aad slices, otherwise should just use aads[0].
        let additional_auth_data = if additional_auth_data.len() == 1 {
            &additional_auth_data[0].to_vec()
        } else {
            &additional_auth_data.concat()
        };

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
        WinCryptoError::from_ntstatus(BCryptDecrypt(
            key.0,
            Some(cipher_text),
            Some(addr_of!(auth_cipher_mode_info) as *const std::ffi::c_void),
            None,
            Some(plain_text),
            &mut count,
            BCRYPT_FLAGS(0),
        ))?;

        Ok(count as usize)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_1() {
        let key =
            WinCryptoSrtpKey::create_aes_ecb_key(&hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c"))
                .unwrap();
        let mut out = [0u8; 32];
        wincrypto_srtp_aes_128_ecb_round(
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
            WinCryptoSrtpKey::create_aes_ecb_key(&hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c"))
                .unwrap();
        let mut out = [0u8; 32];
        wincrypto_srtp_aes_128_ecb_round(
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
            WinCryptoSrtpKey::create_aes_ecb_key(&hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c"))
                .unwrap();
        let mut out = [0u8; 32];
        wincrypto_srtp_aes_128_ecb_round(
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
            WinCryptoSrtpKey::create_aes_ecb_key(&hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c"))
                .unwrap();
        let mut out = [0u8; 32];
        wincrypto_srtp_aes_128_ecb_round(
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
