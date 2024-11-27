use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

pub(super) fn sha1_hmac(key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
    let key = PKey::hmac(key).expect("valid hmac key");
    let mut signer = Signer::new(MessageDigest::sha1(), &key).expect("valid signer");

    for payload in payloads {
        signer.update(payload).expect("signer update");
    }

    let mut hash = [0u8; 20];
    signer.sign(&mut hash).expect("sign to array");
    hash
}
