use windows::{
    core::{HSTRING, PSTR},
    Win32::Security::Cryptography::{
        szOID_RSA_SHA256RSA, BCryptCreateHash, BCryptFinishHash, BCryptGetProperty, BCryptHashData,
        CertCreateSelfSignCertificate, CertFreeCertificateContext, CertStrToNameW,
        BCRYPT_HASH_HANDLE, BCRYPT_OBJECT_LENGTH, BCRYPT_SHA256_ALG_HANDLE, CERT_CONTEXT,
        CERT_CREATE_SELFSIGN_FLAGS, CERT_OID_NAME_STR, CRYPT_ALGORITHM_IDENTIFIER,
        CRYPT_INTEGER_BLOB, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, X509_ASN_ENCODING,
    },
};

use super::WinCryptoError;

#[derive(Debug)]
pub struct WinCryptoCertificate(pub(crate) *const CERT_CONTEXT);
unsafe impl Send for WinCryptoCertificate {}
unsafe impl Sync for WinCryptoCertificate {}

impl WinCryptoCertificate {
    pub fn new_self_signed(subject: &str) -> Result<Self, WinCryptoError> {
        unsafe {
            let subject = HSTRING::from(subject);
            let mut name_blob = CRYPT_INTEGER_BLOB::default();
            CertStrToNameW(
                X509_ASN_ENCODING,
                &subject,
                CERT_OID_NAME_STR,
                None,
                None,
                &mut name_blob.cbData,
                None,
            )?;

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

    pub fn cert_context(&self) -> *const CERT_CONTEXT {
        // TODO(efer): This can probably be removed and use crate visible .0
        self.0
    }

    pub fn sha256_fingerprint(&self) -> Result<[u8; 32], WinCryptoError> {
        unsafe {
            // Determine the size of the scratch space needed to compute a SHA-256 Hash.
            let mut hash_object_size = [0u8; 4];
            let mut hash_object_size_size: u32 = 4;
            if let Err(e) = WinCryptoError::from_ntstatus(BCryptGetProperty(
                BCRYPT_SHA256_ALG_HANDLE,
                BCRYPT_OBJECT_LENGTH,
                Some(&mut hash_object_size),
                &mut hash_object_size_size,
                0,
            )) {
                return Err(WinCryptoError(format!("BCryptGetProperty failed: {e}")));
            }
            let hash_object_len = std::mem::transmute::<[u8; 4], u32>(hash_object_size);
            let mut hash_object = vec![0u8; hash_object_len as usize];

            let mut hash_handle = BCRYPT_HASH_HANDLE::default();
            if let Err(e) = WinCryptoError::from_ntstatus(BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                &mut hash_handle,
                Some(&mut hash_object),
                None,
                0,
            )) {
                return Err(WinCryptoError(format!("Failed to create hash: {e}")));
            }

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

            let mut hash = [0u8; 32];
            WinCryptoError::from_ntstatus(BCryptFinishHash(hash_handle, &mut hash, 0)).map(|_| hash)
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
        unsafe {
            let cert = super::WinCryptoCertificate::new_self_signed("cn=WebRTC").unwrap();

            // Verify it is self-signed.
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
