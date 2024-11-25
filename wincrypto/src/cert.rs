use super::WinCryptoError;
use windows::{
    core::{HSTRING, PSTR},
    Win32::Security::Cryptography::{
        szOID_RSA_SHA256RSA, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptHashData,
        CertCreateSelfSignCertificate, CertFreeCertificateContext, CertStrToNameW,
        BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALG_HANDLE, CERT_CONTEXT, CERT_CREATE_SELFSIGN_FLAGS,
        CERT_OID_NAME_STR, CRYPT_ALGORITHM_IDENTIFIER, CRYPT_INTEGER_BLOB,
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, X509_ASN_ENCODING,
    },
};

#[derive(Debug)]
pub struct WinCryptoCertificate(pub(crate) *const CERT_CONTEXT);
unsafe impl Send for WinCryptoCertificate {}
unsafe impl Sync for WinCryptoCertificate {}

impl WinCryptoCertificate {
    pub fn new_self_signed(subject: &str) -> Result<Self, WinCryptoError> {
        unsafe {
            let subject = HSTRING::from(subject);
            let mut name_blob = CRYPT_INTEGER_BLOB::default();

            // Ask size needed to store Name Blob.
            CertStrToNameW(
                X509_ASN_ENCODING,
                &subject,
                CERT_OID_NAME_STR,
                None,
                None,
                &mut name_blob.cbData,
                None,
            )?;

            // Create buffer for the name blob, and get it filled in.
            let mut name_buffer = vec![0u8; name_blob.cbData as usize];
            name_blob.pbData = name_buffer.as_mut_ptr();
            CertStrToNameW(
                X509_ASN_ENCODING,
                &subject,
                CERT_OID_NAME_STR,
                None,
                Some(name_blob.pbData),
                &mut name_blob.cbData,
                None,
            )?;

            // Use RSA-SHA256 for the signature, since SHA1 is deprecated.
            let signature_algorithm = CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: PSTR::from_raw(szOID_RSA_SHA256RSA.as_ptr() as *mut u8),
                Parameters: CRYPT_INTEGER_BLOB::default(),
            };

            // Generate the self-signed cert.
            let cert_context = CertCreateSelfSignCertificate(
                HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(0),
                &name_blob,
                CERT_CREATE_SELFSIGN_FLAGS(0),
                None,
                Some(&signature_algorithm),
                None,
                None,
                None,
            );

            if cert_context.is_null() {
                Err(WinCryptoError(
                    "Failed to generate self-signed certificate".to_string(),
                ))
            } else {
                Ok(Self(cert_context))
            }
        }
    }

    pub fn sha256_fingerprint(&self) -> Result<[u8; 32], WinCryptoError> {
        unsafe {
            // Create the hash instance.
            let mut hash_handle = BCRYPT_HASH_HANDLE::default();
            if let Err(e) = WinCryptoError::from_ntstatus(BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                &mut hash_handle,
                None,
                None,
                0,
            )) {
                return Err(WinCryptoError(format!("Failed to create hash: {e}")));
            }

            // Hash the certificate contents.
            let cert_info = *self.0;
            if let Err(e) = WinCryptoError::from_ntstatus(BCryptHashData(
                hash_handle,
                std::slice::from_raw_parts(
                    cert_info.pbCertEncoded,
                    cert_info.cbCertEncoded as usize,
                ),
                0,
            )) {
                return Err(WinCryptoError(format!("Failed to hash data: {e}")));
            }

            // Grab the result of the hash.
            let mut hash = [0u8; 32];
            WinCryptoError::from_ntstatus(BCryptFinishHash(hash_handle, &mut hash, 0))?;

            // Destroy the allocated hash.
            WinCryptoError::from_ntstatus(BCryptDestroyHash(hash_handle))?;

            Ok(hash)
        }
    }
}

impl From<*const CERT_CONTEXT> for WinCryptoCertificate {
    fn from(value: *const CERT_CONTEXT) -> Self {
        Self(value)
    }
}

impl Drop for WinCryptoCertificate {
    fn drop(&mut self) {
        unsafe {
            _ = CertFreeCertificateContext(Some(self.0));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn verify_self_signed() {
        let cert = super::WinCryptoCertificate::new_self_signed("cn=WebRTC").unwrap();

        // Verify it is self-signed.
        unsafe {
            let subject = (*(*cert.0).pCertInfo).Subject;
            let subject = std::slice::from_raw_parts(subject.pbData, subject.cbData as usize);
            let issuer = (*(*cert.0).pCertInfo).Issuer;
            let issuer = std::slice::from_raw_parts(issuer.pbData, issuer.cbData as usize);
            assert_eq!(issuer, subject);
        }
    }

    #[test]
    fn verify_fingerprint() {
        let cert = super::WinCryptoCertificate::new_self_signed("cn=WebRTC").unwrap();
        let fingerprint = cert.sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);
    }
}
