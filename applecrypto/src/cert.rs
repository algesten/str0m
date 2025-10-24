use super::AppleCryptoError;

#[derive(Debug)]
pub struct Certificate {}

impl Certificate {
    pub fn new_self_signed(
        _use_ec_dsa_keys: bool,
        _subject: &str,
    ) -> Result<Self, AppleCryptoError> {
        todo!();
    }

    pub fn sha256_fingerprint(&self) -> Result<[u8; 32], AppleCryptoError> {
        let mut _hash = [0u8; 32];
        todo!();
        // Ok(_hash)
    }

    // pub fn context(&self) -> *const CERT_CONTEXT {
    //     self.cert_context
    // }
}

// impl From<*const CERT_CONTEXT> for Certificate {
//     fn from(cert_context: *const CERT_CONTEXT) -> Self {
//         Self {
//             cert_context,
//             key_handle: NCRYPT_KEY_HANDLE::default(),
//         }
//     }
// }

impl Drop for Certificate {
    fn drop(&mut self) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    #[test]
    fn verify_self_signed_rsa() {
        let cert = super::Certificate::new_self_signed(false, "cn=WebRTC-RSA").unwrap();
        let cert_context = cert.context();

        // Verify it is self-signed.
        unsafe {
            assert_eq!(
                CStr::from_ptr(
                    (*(*cert_context).pCertInfo)
                        .SubjectPublicKeyInfo
                        .Algorithm
                        .pszObjId
                        .0 as *const i8
                ),
                CStr::from_ptr(szOID_RSA_RSA.as_ptr() as *const i8)
            );

            let subject = (*(*cert_context).pCertInfo).Subject;
            let issuer = (*(*cert_context).pCertInfo).Issuer;
            // Verify raw contents are equivalent.
            assert_eq!(
                std::slice::from_raw_parts(issuer.pbData, issuer.cbData as usize),
                std::slice::from_raw_parts(subject.pbData, subject.cbData as usize)
            );

            let mut buffer = [0u8; 128];
            CertNameToStrA(
                X509_ASN_ENCODING,
                &subject,
                CERT_X500_NAME_STR,
                Some(&mut buffer),
            );
            let subject = CStr::from_bytes_until_nul(&buffer)
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!("CN=WebRTC-RSA", subject);

            CertNameToStrA(
                X509_ASN_ENCODING,
                &issuer,
                CERT_X500_NAME_STR,
                Some(&mut buffer),
            );
            let issuer = CStr::from_bytes_until_nul(&buffer)
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!("CN=WebRTC-RSA", issuer);
        }
    }

    #[test]
    fn verify_self_signed_ec_dsa() {
        let cert = super::Certificate::new_self_signed(true, "cn=ecDsa").unwrap();
        let cert_context = cert.context();

        // Verify it is self-signed.
        unsafe {
            assert_eq!(
                CStr::from_ptr(
                    (*(*cert_context).pCertInfo)
                        .SubjectPublicKeyInfo
                        .Algorithm
                        .pszObjId
                        .0 as *const i8
                ),
                CStr::from_ptr(szOID_ECC_PUBLIC_KEY.as_ptr() as *const i8)
            );
            let subject = (*(*cert_context).pCertInfo).Subject;
            let issuer = (*(*cert_context).pCertInfo).Issuer;
            // Verify raw contents are equivalent.
            assert_eq!(
                std::slice::from_raw_parts(issuer.pbData, issuer.cbData as usize),
                std::slice::from_raw_parts(subject.pbData, subject.cbData as usize)
            );

            let mut buffer = [0u8; 128];
            CertNameToStrA(
                X509_ASN_ENCODING,
                &subject,
                CERT_X500_NAME_STR,
                Some(&mut buffer),
            );
            let subject = CStr::from_bytes_until_nul(&buffer)
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!("CN=ecDsa", subject);

            CertNameToStrA(
                X509_ASN_ENCODING,
                &issuer,
                CERT_X500_NAME_STR,
                Some(&mut buffer),
            );
            let issuer = CStr::from_bytes_until_nul(&buffer)
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!("CN=ecDsa", issuer);
        }
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
