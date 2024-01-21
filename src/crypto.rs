pub fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
    use hmac::Hmac;
    use hmac::Mac;
    use sha1::Sha1;

    let mut hmac = Hmac::<Sha1>::new_from_slice(key).unwrap();

    for payload in payloads {
        hmac.update(payload);
    }

    hmac.finalize().into_bytes().into()
}
