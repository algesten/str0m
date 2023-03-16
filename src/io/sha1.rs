/// The sha1 hmac checks of SRTP packets is one of the most expensive operations.
/// The sha-1 crate with feature "asm" seems to be the most performant way of doing it,
/// however the "asm" feature doesn't work on windows. The Sha1 struct uses openssl for
/// windows, and the sha-1 crate for unix.

#[cfg(windows)]
#[derive(Clone)]
pub struct Sha1(std::sync::Arc<openssl::pkey::PKey<openssl::pkey::Private>>);

#[cfg(windows)]
impl Sha1 {
    pub fn hmac(self, payloads: &[&[u8]]) -> [u8; 20] {
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;

        let mut signer = Signer::new(MessageDigest::sha1(), &self.0).unwrap();
        for payload in payloads {
            signer.update(payload).unwrap();
        }

        let mut out = [0; 20];
        signer.sign(&mut out).unwrap();

        out
    }
}

#[cfg(windows)]
impl From<&[u8]> for Sha1 {
    fn from(value: &[u8]) -> Self {
        Sha1(std::sync::Arc::new(
            openssl::pkey::PKey::hmac(value).unwrap(),
        ))
    }
}

#[cfg(unix)]
#[derive(Clone)]
pub struct Sha1(hmac::Hmac<sha1::Sha1>);

#[cfg(unix)]
impl Sha1 {
    pub fn hmac(mut self, payloads: &[&[u8]]) -> [u8; 20] {
        use hmac::Mac;
        for payload in payloads {
            self.0.update(payload);
        }

        let comp = self.0.finalize().into_bytes();
        comp.into()
    }
}

#[cfg(unix)]
impl From<&[u8]> for Sha1 {
    fn from(value: &[u8]) -> Self {
        use hmac::Hmac;
        use hmac::Mac;
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;
        Sha1(HmacSha1::new_from_slice(value).unwrap())
    }
}
