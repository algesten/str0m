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

/// Certificate wraps the CERT_CONTEXT pointer, so that it can be destroyed
/// when it is no longer used. Because it is tracked, it is important that
/// Certificate does NOT implement Clone/Copy, otherwise we could destroy the
/// Certificate too early. It is also why access to the certificate pointer
/// should remain hidden.
#[derive(Debug)]
pub struct Certificate(pub(crate) *const CERT_CONTEXT);
// SAFETY: CERT_CONTEXT pointers are safe to send between threads.
unsafe impl Send for Certificate {}
// SAFETY: CERT_CONTEXT pointers are safe to send between threads.
unsafe impl Sync for Certificate {}

impl Certificate {
    pub fn new_self_signed(subject: &str) -> Result<Self, WinCryptoError> {
        let subject = HSTRING::from(subject);
        let mut subject_blob_buffer = vec![0u8; 256];
        let mut subject_blob = CRYPT_INTEGER_BLOB {
            cbData: subject_blob_buffer.len() as u32,
            pbData: subject_blob_buffer.as_mut_ptr(),
        };

        // Use RSA-SHA256 for the signature, since SHA1 is deprecated.
        let signature_algorithm = CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: PSTR::from_raw(szOID_RSA_SHA256RSA.as_ptr() as *mut u8),
            Parameters: CRYPT_INTEGER_BLOB::default(),
        };

        // SAFETY: The Windows APIs accept references, so normal borrow checker
        // behaviors work for those uses. The name_blob has a pointer to the buffer
        // which must exist for the duration of the unsafe block.
        unsafe {
            CertStrToNameW(
                X509_ASN_ENCODING,
                &subject,
                CERT_OID_NAME_STR,
                None,
                Some(subject_blob.pbData),
                &mut subject_blob.cbData,
                None,
            )?;

            // Generate the self-signed cert.
            let cert_context = CertCreateSelfSignCertificate(
                HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(0),
                &subject_blob,
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
        let mut hash = [0u8; 32];
        let mut hash_handle = BCRYPT_HASH_HANDLE::default();

        // SAFETY: The Windows APIs accept references, so normal borrow checker
        // behaviors work for those uses.
        unsafe {
            // Create the hash instance.
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
            WinCryptoError::from_ntstatus(BCryptFinishHash(hash_handle, &mut hash, 0))?;

            // Destroy the allocated hash.
            WinCryptoError::from_ntstatus(BCryptDestroyHash(hash_handle))?;
        }
        Ok(hash)
    }
}

impl From<*const CERT_CONTEXT> for Certificate {
    fn from(value: *const CERT_CONTEXT) -> Self {
        Self(value)
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: The Certificate is no longer usable, so it's safe to pass the pointer
        // to Windows for release.
        unsafe {
            _ = CertFreeCertificateContext(Some(self.0));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn verify_self_signed() {
        let cert = super::Certificate::new_self_signed("cn=WebRTC").unwrap();

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
        let cert = super::Certificate::new_self_signed("cn=WebRTC").unwrap();
        let fingerprint = cert.sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);
    }
}
