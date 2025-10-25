use super::apple_common_crypto::*;
use super::AppleCryptoError;
use std::ffi::c_void;
use std::ptr;

const MAX_BUFFER_SIZE: usize = 2048;
const AEAD_AES_GCM_TAG_LEN: usize = 16;

/// SRTP Key wraps the key data for AES operations. Because it is tracked,
/// it is important that SrtpKey does NOT implement Clone/Copy, otherwise
/// we could have security issues with key material duplication.
///
/// This implementation uses Apple's CommonCrypto framework for AES operations.
pub struct SrtpKey {
    key_data: Vec<u8>,
}

impl SrtpKey {
    /// Creates a key from the given data for operating AES in Counter (CTR/CM) mode.
    pub fn create_aes_ctr_key(key: &[u8]) -> Result<Self, AppleCryptoError> {
        // CTR mode is build on top of ECB mode, so we use the same key.
        Self::create_aes_ecb_key(key)
    }

    /// Creates a key from the given data for operating AES in ECB mode.
    pub fn create_aes_ecb_key(key: &[u8]) -> Result<Self, AppleCryptoError> {
        // Validate key size
        match key.len() {
            K_CC_AES_KEY_SIZE_128 | K_CC_AES_KEY_SIZE_192 | K_CC_AES_KEY_SIZE_256 => Ok(SrtpKey {
                key_data: key.to_vec(),
            }),
            _ => Err(format!("Invalid AES key size: {}", key.len()).into()),
        }
    }

    /// Creates a key from the given data for operating AES in GCM mode.
    pub fn create_aes_gcm_key(key: &[u8]) -> Result<Self, AppleCryptoError> {
        // GCM mode uses the same key validation as ECB
        Self::create_aes_ecb_key(key)
    }
}

impl Drop for SrtpKey {
    /// Securely clear the key material when the key is dropped
    fn drop(&mut self) {
        // Zero out the key data for security
        self.key_data.fill(0);
    }
}

/// Run the given input through the AES-xxx-ECB using the given AES ECB key.
pub fn srtp_aes_ecb_round(
    key: &SrtpKey,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, AppleCryptoError> {
    if input.len() != 16 {
        return Err("Input must be exactly 16 bytes for AES block".into());
    }
    if output.len() < 16 {
        return Err("Output buffer must be at least 16 bytes".into());
    }

    let mut cryptor: *mut c_void = ptr::null_mut();

    // Create ECB mode cryptor
    let status = unsafe {
        CCCryptorCreate(
            K_CC_ENCRYPT,
            K_CC_ALGORITHM_AES,
            K_CC_OPTION_ECB_MODE,
            key.key_data.as_ptr(),
            key.key_data.len(),
            ptr::null(), // No IV for ECB
            &mut cryptor,
        )
    };

    if status != 0 {
        return Err(format!("Failed to create AES ECB cryptor: {}", status).into());
    }

    let mut data_out_moved = 0usize;

    // Encrypt the input
    let status = unsafe {
        CCCryptorUpdate(
            cryptor,
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut data_out_moved,
        )
    };

    if status != 0 {
        unsafe { CCCryptorRelease(cryptor) };
        return Err(format!("Failed to encrypt data: {}", status).into());
    }

    let mut final_moved = 0usize;
    let status = unsafe {
        CCCryptorFinal(
            cryptor,
            output.as_mut_ptr().add(data_out_moved),
            output.len() - data_out_moved,
            &mut final_moved,
        )
    };

    unsafe { CCCryptorRelease(cryptor) };

    if status != 0 {
        return Err(format!("Failed to finalize encryption: {}", status).into());
    }

    Ok(data_out_moved + final_moved)
}

/// Run the given input through the AES-128-CM using the given AES CTR/CM key.
pub fn srtp_aes_128_cm(
    key: &SrtpKey,
    iv: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, AppleCryptoError> {
    if output.len() < input.len() {
        return Err("Output buffer too small".into());
    }

    // First, we'll make a copy of the IV with a counter as many times as
    // needed into a new countered_iv.
    let mut iv = iv.to_vec();
    let mut countered_iv = [0u8; MAX_BUFFER_SIZE];
    let mut offset = 0;
    while offset < input.len() {
        let start = offset;
        let end = std::cmp::min(offset + 16, countered_iv.len());
        if end > start {
            countered_iv[start..end].copy_from_slice(&iv[..end - start]);
        }
        offset += 16;

        // Increment counter in IV (big-endian)
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

    // Now encrypt the countered IV to create the keystream
    let blocks_needed = (input.len() + 15) / 16;
    let mut keystream = vec![0u8; blocks_needed * 16];

    for i in 0..blocks_needed {
        let block_start = i * 16;
        let block_end = block_start + 16;
        let mut block_output = [0u8; 16];

        srtp_aes_ecb_round(
            key,
            &countered_iv[block_start..block_end],
            &mut block_output,
        )?;
        keystream[block_start..block_end].copy_from_slice(&block_output);
    }

    // XOR input with keystream to get output
    for (i, &input_byte) in input.iter().enumerate() {
        output[i] = input_byte ^ keystream[i];
    }

    Ok(input.len())
}

/// Run the given plain_text through the AES-GCM alg with the given key and receive the
/// cipher_text which will include the auth tag.
pub fn srtp_aead_aes_gcm_encrypt(
    key: &SrtpKey,
    iv: &[u8],
    additional_auth_data: &[u8],
    plain_text: &[u8],
    cipher_text: &mut [u8],
) -> Result<usize, AppleCryptoError> {
    if cipher_text.len() < plain_text.len() + AEAD_AES_GCM_TAG_LEN {
        return Err("Cipher Text is too small to include TAG".into());
    }

    assert!(
        additional_auth_data.len() >= 12,
        "Associated data length MUST be at least 12 octets"
    );

    let mut cryptor: *mut c_void = ptr::null_mut();

    // Create GCM mode cryptor
    let status = unsafe {
        CCCryptorCreateWithMode(
            K_CC_ENCRYPT,
            K_CC_MODE_GCM,
            K_CC_ALGORITHM_AES,
            0,           // No padding for GCM
            ptr::null(), // IV will be added separately
            key.key_data.as_ptr(),
            key.key_data.len(),
            ptr::null(), // No tweak
            0,           // No tweak length
            0,           // Default rounds
            0,           // No mode options
            &mut cryptor,
        )
    };

    if status != 0 {
        return Err(format!("Failed to create AES GCM cryptor: {}", status).into());
    }

    // Add IV
    let status = unsafe { CCCryptorGCMAddIV(cryptor, iv.as_ptr(), iv.len()) };
    if status != 0 {
        unsafe { CCCryptorRelease(cryptor) };
        return Err(format!("Failed to add IV: {}", status).into());
    }

    // Add additional authenticated data
    let status = unsafe {
        CCCryptorGCMAddAAD(
            cryptor,
            additional_auth_data.as_ptr(),
            additional_auth_data.len(),
        )
    };
    if status != 0 {
        unsafe { CCCryptorRelease(cryptor) };
        return Err(format!("Failed to add AAD: {}", status).into());
    }

    // Encrypt the plaintext
    let status = unsafe {
        CCCryptorGCMEncrypt(
            cryptor,
            plain_text.as_ptr(),
            plain_text.len(),
            cipher_text.as_mut_ptr(),
        )
    };
    if status != 0 {
        unsafe { CCCryptorRelease(cryptor) };
        return Err(format!("Failed to encrypt: {}", status).into());
    }

    // Get the authentication tag
    let mut tag_len = AEAD_AES_GCM_TAG_LEN;
    let tag_ptr = unsafe { cipher_text.as_mut_ptr().add(plain_text.len()) };
    let status = unsafe { CCCryptorGCMFinal(cryptor, tag_ptr, &mut tag_len) };

    unsafe { CCCryptorRelease(cryptor) };

    if status != 0 {
        return Err(format!("Failed to get authentication tag: {}", status).into());
    }

    Ok(plain_text.len() + tag_len)
}

/// Run the given tagged cipher_text through the AES-GCM alg with the given key and
/// receive the decrypted plain_text.
pub fn srtp_aead_aes_gcm_decrypt(
    key: &SrtpKey,
    iv: &[u8],
    additional_auth_data: &[&[u8]],
    cipher_text: &[u8],
    plain_text: &mut [u8],
) -> Result<usize, AppleCryptoError> {
    if cipher_text.len() < AEAD_AES_GCM_TAG_LEN {
        return Err("Cipher Text too short to include tag".into());
    }
    let (cipher_data, tag) = cipher_text.split_at(cipher_text.len() - AEAD_AES_GCM_TAG_LEN);

    if plain_text.len() < cipher_data.len() {
        return Err("Plain text buffer too small".into());
    }

    // If we don't have exactly one auth_data, we need to flatten it. This will
    // hold our reference to the data.
    let flattened_auth_data = if additional_auth_data.len() != 1 {
        Some(additional_auth_data.concat())
    } else {
        None
    };
    let additional_auth_data_slice = flattened_auth_data
        .as_ref()
        .map_or(additional_auth_data[0], |f| f.as_slice());

    let mut cryptor: *mut c_void = ptr::null_mut();

    // Create GCM mode cryptor for decryption
    let status = unsafe {
        CCCryptorCreateWithMode(
            K_CC_DECRYPT,
            K_CC_MODE_GCM,
            K_CC_ALGORITHM_AES,
            0,           // No padding for GCM
            ptr::null(), // IV will be added separately
            key.key_data.as_ptr(),
            key.key_data.len(),
            ptr::null(), // No tweak
            0,           // No tweak length
            0,           // Default rounds
            0,           // No mode options
            &mut cryptor,
        )
    };

    if status != 0 {
        return Err(format!("Failed to create AES GCM cryptor: {}", status).into());
    }

    // Add IV
    let status = unsafe { CCCryptorGCMAddIV(cryptor, iv.as_ptr(), iv.len()) };
    if status != 0 {
        unsafe { CCCryptorRelease(cryptor) };
        return Err(format!("Failed to add IV: {}", status).into());
    }

    // Add additional authenticated data
    let status = unsafe {
        CCCryptorGCMAddAAD(
            cryptor,
            additional_auth_data_slice.as_ptr(),
            additional_auth_data_slice.len(),
        )
    };
    if status != 0 {
        unsafe { CCCryptorRelease(cryptor) };
        return Err(format!("Failed to add AAD: {}", status).into());
    }

    // Decrypt the ciphertext
    let status = unsafe {
        CCCryptorGCMDecrypt(
            cryptor,
            cipher_data.as_ptr(),
            cipher_data.len(),
            plain_text.as_mut_ptr(),
        )
    };
    if status != 0 {
        unsafe { CCCryptorRelease(cryptor) };
        return Err(format!("Failed to decrypt: {}", status).into());
    }

    // Verify the authentication tag
    let mut computed_tag = [0u8; AEAD_AES_GCM_TAG_LEN];
    let mut tag_len = AEAD_AES_GCM_TAG_LEN;
    let status = unsafe { CCCryptorGCMFinal(cryptor, computed_tag.as_mut_ptr(), &mut tag_len) };

    unsafe { CCCryptorRelease(cryptor) };

    if status != 0 {
        return Err(format!("Failed to get authentication tag: {}", status).into());
    }

    // Compare the tags
    if tag != &computed_tag[..tag_len] {
        return Err("Authentication tag verification failed".into());
    }

    Ok(cipher_data.len())
}

#[cfg(test)]
mod test {
    use super::*;

    // The test vectors in the following tests come from:
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

    #[test]
    fn test_srtp_aes_128_ecb_round_test_vec_1() {
        let key =
            SrtpKey::create_aes_ecb_key(&hex_to_vec("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        let mut out = [0u8; 32];
        srtp_aes_ecb_round(
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
        srtp_aes_ecb_round(
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
        srtp_aes_ecb_round(
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
        srtp_aes_ecb_round(
            &key,
            &hex_to_vec("f69f2445df4f9b17ad2b417be66c3710"),
            &mut out,
        )
        .unwrap();
        assert_eq!(slice_to_hex(&out[..16]), "7b0c785e27e8ad3f8223207104725dd4");
    }

    #[test]
    fn test_srtp_aes_256_ecb_round_test_vec_1() {
        let key = SrtpKey::create_aes_ecb_key(&hex_to_vec(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ))
        .unwrap();
        let mut out = [0u8; 32];
        srtp_aes_ecb_round(
            &key,
            &hex_to_vec("6bc1bee22e409f96e93d7e117393172a"),
            &mut out,
        )
        .unwrap();
        assert_eq!(slice_to_hex(&out[..16]), "f3eed1bdb5d2a03c064b5a7e3db181f8");
    }

    #[test]
    fn test_srtp_aes_256_ecb_round_test_vec_2() {
        let key = SrtpKey::create_aes_ecb_key(&hex_to_vec(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ))
        .unwrap();
        let mut out = [0u8; 32];
        srtp_aes_ecb_round(
            &key,
            &hex_to_vec("ae2d8a571e03ac9c9eb76fac45af8e51"),
            &mut out,
        )
        .unwrap();
        assert_eq!(slice_to_hex(&out[..16]), "591ccb10d410ed26dc5ba74a31362870");
    }

    #[test]
    fn test_srtp_aes_256_ecb_round_test_vec_3() {
        let key = SrtpKey::create_aes_ecb_key(&hex_to_vec(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ))
        .unwrap();
        let mut out = [0u8; 32];
        srtp_aes_ecb_round(
            &key,
            &hex_to_vec("30c81c46a35ce411e5fbc1191a0a52ef"),
            &mut out,
        )
        .unwrap();
        assert_eq!(slice_to_hex(&out[..16]), "b6ed21b99ca6f4f9f153e7b1beafed1d");
    }

    #[test]
    fn test_srtp_aes_256_ecb_round_test_vec_4() {
        let key = SrtpKey::create_aes_ecb_key(&hex_to_vec(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ))
        .unwrap();
        let mut out = [0u8; 32];
        srtp_aes_ecb_round(
            &key,
            &hex_to_vec("f69f2445df4f9b17ad2b417be66c3710"),
            &mut out,
        )
        .unwrap();
        assert_eq!(slice_to_hex(&out[..16]), "23304b7a39f9f3ff067d8d8f9e24ecc7");
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
