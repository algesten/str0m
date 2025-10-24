use super::AppleCryptoError;

const MAX_BUFFER_SIZE: usize = 2048;
const AEAD_AES_GCM_TAG_LEN: usize = 16;

/// SRTP Key wraps the CNG key, so that it can be destroyed when it is
/// no longer used. Because it is tracked, it is important that StrpKey
/// does NOT implement Clone/Copy, otherwise we could destroy the key
/// too early. It is also why access to the key handle should remain
/// hidden.
pub struct SrtpKey {}

impl SrtpKey {
    /// Creates a key from the given data for operating AES in Counter (CTR/CM) mode.
    pub fn create_aes_ctr_key(key: &[u8]) -> Result<Self, AppleCryptoError> {
        // CTR mode is build on top of ECB mode, so we use the same key.
        Self::create_aes_ecb_key(key)
    }

    /// Creates a key from the given data for operating AES in ECB mode.
    pub fn create_aes_ecb_key(_key: &[u8]) -> Result<Self, AppleCryptoError> {
        todo!()
    }

    /// Creates a key from the given data for operating AES in GCM mode.
    pub fn create_aes_gcm_key(_key: &[u8]) -> Result<Self, AppleCryptoError> {
        todo!()
    }
}

/// Run the given input through the AES-xxx-ECB using the given AES ECB key.
pub fn srtp_aes_ecb_round(
    _key: &SrtpKey,
    _input: &[u8],
    _output: &mut [u8],
) -> Result<usize, AppleCryptoError> {
    todo!();
}

/// Run the given input through the AES-128-CM using the given AES CTR/CM key.
pub fn srtp_aes_128_cm(
    _key: &SrtpKey,
    iv: &[u8],
    input: &[u8],
    _output: &mut [u8],
) -> Result<usize, AppleCryptoError> {
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

    todo!();
}

/// Run the given plain_text through the AES-GCM alg with the given key and receive the
/// cipher_text which will include the auth tag.
pub fn srtp_aead_aes_gcm_encrypt(
    _key: &SrtpKey,
    _iv: &[u8],
    additional_auth_data: &[u8],
    plain_text: &[u8],
    cipher_text: &mut [u8],
) -> Result<usize, AppleCryptoError> {
    if cipher_text.len() < plain_text.len() {
        return Err("Cipher Text is to small to include TAG".into());
    }

    assert!(
        additional_auth_data.len() >= 12,
        "Associated data length MUST be at least 12 octets"
    );

    todo!();
}

/// Run the given tagged cipher_text through the AES-GCM alg with the given key and
/// receive the decrypted plain_text.
pub fn srtp_aead_aes_gcm_decrypt(
    _key: &SrtpKey,
    _iv: &[u8],
    additional_auth_data: &[&[u8]],
    cipher_text: &[u8],
    _plain_text: &mut [u8],
) -> Result<usize, AppleCryptoError> {
    if cipher_text.len() < AEAD_AES_GCM_TAG_LEN {
        return Err("Cipher Text too short to include tag".into());
    }
    let (_cipher_text, _tag) = cipher_text.split_at(cipher_text.len() - AEAD_AES_GCM_TAG_LEN);

    // If don't have exactly one auth_data, we need to flatten it. This will
    // hold our reference to the data.
    let flattened_auth_data = if additional_auth_data.len() != 1 {
        Some(additional_auth_data.concat())
    } else {
        None
    };
    let _additional_auth_data = flattened_auth_data
        .as_ref()
        .map_or(additional_auth_data[0], |f| f.as_slice());

    todo!();
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
