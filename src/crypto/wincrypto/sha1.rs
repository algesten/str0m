use str0m_wincrypto::wincrypto_sha1_hmac;

pub fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
    match wincrypto_sha1_hmac(key, payloads) {
        Ok(hash) => hash,
        Err(e) => panic!("sha1_hmac failed in WinCrypto: {e}"),
    }
}
