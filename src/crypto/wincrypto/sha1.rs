use str0m_wincrypto::wincrypto_sha1_hmac;

#[allow(dead_code)] // If 'sha1' feature is enabled this is not used.
pub fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
    match wincrypto_sha1_hmac(key, payloads) {
        Ok(hash) => hash,
        Err(e) => panic!("sha1_hmac failed in WinCrypto: {e}"),
    }
}
