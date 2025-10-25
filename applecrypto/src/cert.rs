use super::apple_common_crypto::{CC_SHA256, CC_SHA256_DIGEST_LENGTH};
use super::AppleCryptoError;
use security_framework::key::SecKey;
use std::ffi::c_void;

#[derive(Debug)]
pub struct Certificate {}

impl Certificate {
    pub fn new_self_signed(use_ec_dsa_keys: bool, subject: &str) -> Result<Self, AppleCryptoError> {
        todo!();
    }

    pub fn sha256_fingerprint(&self) -> Result<[u8; 32], AppleCryptoError> {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn verify_self_signed_rsa() {
        let cert = super::Certificate::new_self_signed(false, "cn=WebRTC-RSA").unwrap();

        // TODO: Verify subject and issuer are the same
        // TODO: Verify subject common name is cn=WebRTC-RSA
        // TODO: Verify issuer common name is cn=WebRTC-RSA
    }

    #[test]
    fn verify_self_signed_ec_dsa() {
        let cert = super::Certificate::new_self_signed(true, "cn=ecDsa").unwrap();

        // TODO: Verify subject and issuer are the same
        // TODO: Verify subject common name is cn=ecDsa
        // TODO: Verify issuer common name is cn=ecDsa
    }

    #[test]
    fn verify_fingerprint_rsa() {
        let cert = super::Certificate::new_self_signed(false, "cn=WebRTC").unwrap();
        let fingerprint = cert.sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);
    }

    #[test]
    fn verify_fingerprint_ec_dsa() {
        let cert = super::Certificate::new_self_signed(true, "cn=WebRTC").unwrap();
        let fingerprint = cert.sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);
    }
}
