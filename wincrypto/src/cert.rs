use super::WinCryptoError;
use windows::{
    core::{Owned, GUID, HSTRING, PSTR, PWSTR},
    Win32::{
        Foundation::GetLastError,
        Security::Cryptography::{
            szOID_ECDSA_SHA256, szOID_RSA_SHA256RSA, BCryptCreateHash, BCryptFinishHash,
            BCryptHashData, CertCreateSelfSignCertificate, CertFreeCertificateContext,
            CertStrToNameW, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptFinalizeKey,
            NCryptOpenStorageProvider, BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALG_HANDLE, CERT_CONTEXT,
            CERT_CREATE_SELFSIGN_FLAGS, CERT_KEY_SPEC, CERT_OID_NAME_STR,
            CRYPT_ALGORITHM_IDENTIFIER, CRYPT_INTEGER_BLOB, CRYPT_KEY_PROV_INFO,
            HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, MS_KEY_STORAGE_PROVIDER, NCRYPT_ECDSA_P256_ALGORITHM,
            NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
            X509_ASN_ENCODING,
        },
        System::Rpc::{UuidCreate, UuidToStringW, RPC_S_OK},
    },
};

/// Certificate wraps the CERT_CONTEXT pointer, so that it can be destroyed
/// when it is no longer used. Because it is tracked, it is important that
/// Certificate does NOT implement Clone/Copy, otherwise we could destroy the
/// Certificate too early. It is also why access to the certificate pointer
/// should remain hidden.
#[derive(Debug)]
pub struct Certificate {
    cert_context: *const CERT_CONTEXT,
    key_handle: NCRYPT_KEY_HANDLE,
}
// SAFETY: CERT_CONTEXT pointers are safe to send between threads.
unsafe impl Send for Certificate {}
// SAFETY: CERT_CONTEXT pointers are safe to send between threads.
unsafe impl Sync for Certificate {}

impl Certificate {
    pub fn new_self_signed(use_ec_dsa_keys: bool, subject: &str) -> Result<Self, WinCryptoError> {
        let subject = HSTRING::from(subject);
        let mut subject_blob_buffer = vec![0u8; 256];
        let mut subject_blob = CRYPT_INTEGER_BLOB {
            cbData: subject_blob_buffer.len() as u32,
            pbData: subject_blob_buffer.as_mut_ptr(),
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

            let mut key_handle = NCRYPT_KEY_HANDLE::default();

            // Generate the self-signed cert.
            let cert_context = if use_ec_dsa_keys {
                let mut guid = GUID::default();
                let result = UuidCreate(&mut guid);
                if result != RPC_S_OK {
                    return Err(WinCryptoError(format!(
                        "Failed to generate GUID for EC-DSA key: {:?}",
                        result
                    )));
                }
                // A formated UUID is 20 characters long, plus null termination.
                let mut guid_buffer = [0u16; 42];
                let mut guid_pwstr = PWSTR::from_raw(guid_buffer.as_mut_ptr());
                let result = UuidToStringW(&guid, &mut guid_pwstr);
                if result != RPC_S_OK {
                    return Err(WinCryptoError(format!(
                        "Failed to format GUID for EC-DSA key: {:?}",
                        result
                    )));
                }

                // We need to first create a EC-DSA key. We need to use NCrypt APIs
                // for this, although we don't really want to persist this key.
                let mut h_provider = Owned::new(NCRYPT_PROV_HANDLE::default());
                NCryptOpenStorageProvider(&mut *h_provider, MS_KEY_STORAGE_PROVIDER, 0)?;

                NCryptCreatePersistedKey(
                    *h_provider,
                    &mut key_handle,
                    // Use EC-256 which corresponds to NID_X9_62_prime256v1
                    NCRYPT_ECDSA_P256_ALGORITHM,
                    // Passing None makes this key ephemeral and not persisted.
                    guid_pwstr,
                    CERT_KEY_SPEC(0),
                    NCRYPT_SILENT_FLAG,
                )?;
                NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0))?;

                let key_prov_info = CRYPT_KEY_PROV_INFO {
                    pwszContainerName: guid_pwstr,
                    pwszProvName: PWSTR(MS_KEY_STORAGE_PROVIDER.as_ptr() as *mut u16),
                    ..Default::default()
                };

                let signature_algorithm = CRYPT_ALGORITHM_IDENTIFIER {
                    pszObjId: PSTR::from_raw(szOID_ECDSA_SHA256.as_ptr() as *mut u8),
                    ..Default::default()
                };

                CertCreateSelfSignCertificate(
                    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(key_handle.0),
                    &subject_blob,
                    CERT_CREATE_SELFSIGN_FLAGS(0),
                    Some(&key_prov_info as *const _ as *const _),
                    Some(&signature_algorithm),
                    None,
                    None,
                    None,
                )
            } else {
                // Use RSA-SHA256 for the signature, since SHA1 is deprecated.
                let signature_algorithm = CRYPT_ALGORITHM_IDENTIFIER {
                    pszObjId: PSTR::from_raw(szOID_RSA_SHA256RSA.as_ptr() as *mut u8),
                    ..Default::default()
                };

                CertCreateSelfSignCertificate(
                    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(0),
                    &subject_blob,
                    CERT_CREATE_SELFSIGN_FLAGS(0),
                    None,
                    Some(&signature_algorithm),
                    None,
                    None,
                    None,
                )
            };

            if cert_context.is_null() {
                let win_err = GetLastError();
                Err(WinCryptoError(format!(
                    "Failed to generate self-signed certificate: {:?}",
                    win_err
                )))
            } else {
                Ok(Self {
                    cert_context,
                    key_handle,
                })
            }
        }
    }

    pub fn sha256_fingerprint(&self) -> Result<[u8; 32], WinCryptoError> {
        let mut hash = [0u8; 32];
        // SAFETY: The Windows APIs accept references, so normal borrow checker
        // behaviors work for those uses.
        unsafe {
            let mut hash_handle = Owned::new(BCRYPT_HASH_HANDLE::default());
            // Create the hash instance.
            if let Err(e) = WinCryptoError::from_ntstatus(BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                &mut *hash_handle,
                None,
                None,
                0,
            )) {
                return Err(WinCryptoError(format!("Failed to create hash: {e}")));
            }

            // Hash the certificate contents.
            let cert_info = *self.cert_context;
            if let Err(e) = WinCryptoError::from_ntstatus(BCryptHashData(
                *hash_handle,
                std::slice::from_raw_parts(
                    cert_info.pbCertEncoded,
                    cert_info.cbCertEncoded as usize,
                ),
                0,
            )) {
                return Err(WinCryptoError(format!("Failed to hash data: {e}")));
            }

            // Grab the result of the hash.
            WinCryptoError::from_ntstatus(BCryptFinishHash(*hash_handle, &mut hash, 0))?;
        }
        Ok(hash)
    }

    pub fn context(&self) -> *const CERT_CONTEXT {
        self.cert_context
    }
}

impl From<*const CERT_CONTEXT> for Certificate {
    fn from(cert_context: *const CERT_CONTEXT) -> Self {
        Self {
            cert_context,
            key_handle: NCRYPT_KEY_HANDLE::default(),
        }
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: The Certificate is no longer usable, so it's safe to pass the pointer
        // to Windows for release.
        unsafe {
            _ = CertFreeCertificateContext(Some(self.cert_context));
            _ = NCryptDeleteKey(self.key_handle, NCRYPT_SILENT_FLAG.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use windows::Win32::Security::Cryptography::{
        szOID_ECC_PUBLIC_KEY, szOID_RSA_RSA, CertNameToStrA, CERT_X500_NAME_STR, X509_ASN_ENCODING,
    };

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
