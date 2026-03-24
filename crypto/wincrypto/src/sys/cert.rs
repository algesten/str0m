use super::WinCryptoError;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Security::Cryptography::CERT_CONTEXT;
use windows::Win32::Security::Cryptography::CERT_CREATE_SELFSIGN_FLAGS;
use windows::Win32::Security::Cryptography::CERT_KEY_SPEC;
use windows::Win32::Security::Cryptography::CERT_OID_NAME_STR;
use windows::Win32::Security::Cryptography::CRYPT_ALGORITHM_IDENTIFIER;
use windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB;
use windows::Win32::Security::Cryptography::CRYPT_KEY_PROV_INFO;
use windows::Win32::Security::Cryptography::CertCreateSelfSignCertificate;
use windows::Win32::Security::Cryptography::CertFreeCertificateContext;
use windows::Win32::Security::Cryptography::CertStrToNameW;
use windows::Win32::Security::Cryptography::HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
use windows::Win32::Security::Cryptography::MS_KEY_STORAGE_PROVIDER;
use windows::Win32::Security::Cryptography::NCRYPT_ECDSA_P256_ALGORITHM;
use windows::Win32::Security::Cryptography::NCRYPT_FLAGS;
use windows::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE;
use windows::Win32::Security::Cryptography::NCRYPT_PROV_HANDLE;
use windows::Win32::Security::Cryptography::NCRYPT_SILENT_FLAG;
use windows::Win32::Security::Cryptography::NCryptCreatePersistedKey;
use windows::Win32::Security::Cryptography::NCryptDeleteKey;
use windows::Win32::Security::Cryptography::NCryptFinalizeKey;
use windows::Win32::Security::Cryptography::NCryptOpenStorageProvider;
use windows::Win32::Security::Cryptography::X509_ASN_ENCODING;
use windows::Win32::Security::Cryptography::szOID_ECDSA_SHA256;
use windows::Win32::Security::Cryptography::szOID_RSA_SHA256RSA;
use windows::Win32::System::Rpc::UuidCreate;
use windows::Win32::System::Rpc::UuidToStringW;
use windows::core::GUID;
use windows::core::HSTRING;
use windows::core::Owned;
use windows::core::PSTR;
use windows::core::PWSTR;

/// Certificate wraps the CERT_CONTEXT pointer, so that it can be destroyed
/// when it is no longer used. Because it is tracked, it is important that
/// Certificate does NOT implement Clone/Copy, otherwise we could destroy the
/// Certificate too early. It is also why access to the certificate pointer
/// should remain hidden.
#[derive(Debug)]
pub struct Certificate {
    cert_context: *const CERT_CONTEXT,
    key_handle: Option<NCRYPT_KEY_HANDLE>,
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

            // Generate the self-signed cert.
            let (cert_context, key_handle) = if use_ec_dsa_keys {
                let mut key_handle = NCRYPT_KEY_HANDLE::default();
                let mut guid = GUID::default();
                let result = UuidCreate(&mut guid);
                WinCryptoError::from_rpc_status(result)?;

                // A formated UUID is 20 characters long, plus null termination.
                let mut guid_buffer = [0u16; 42];
                let mut guid_pwstr = PWSTR::from_raw(guid_buffer.as_mut_ptr());
                let result = UuidToStringW(&guid, &mut guid_pwstr);
                WinCryptoError::from_rpc_status(result)?;

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

                // Dimpl currently requires the Certificate and Private Key as
                // DER-encoded bytes. This will allow plaintext export so the
                // private key can be exported in PKCS#8 format after creation.
                #[cfg(feature = "prefer_dimpl")]
                {
                    use windows::Win32::Security::Cryptography::NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
                    use windows::Win32::Security::Cryptography::NCRYPT_EXPORT_POLICY_PROPERTY;
                    use windows::Win32::Security::Cryptography::NCryptSetProperty;
                    let export_policy = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
                    NCryptSetProperty(
                        key_handle.into(),
                        NCRYPT_EXPORT_POLICY_PROPERTY,
                        &export_policy.to_le_bytes(),
                        NCRYPT_SILENT_FLAG,
                    )?;
                }

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

                (
                    CertCreateSelfSignCertificate(
                        Some(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(key_handle.0)),
                        &subject_blob,
                        CERT_CREATE_SELFSIGN_FLAGS(0),
                        Some(&key_prov_info as *const _ as *const _),
                        Some(&signature_algorithm),
                        None,
                        None,
                        None,
                    ),
                    Some(key_handle),
                )
            } else {
                // Use RSA-SHA256 for the signature, since SHA1 is deprecated.
                let signature_algorithm = CRYPT_ALGORITHM_IDENTIFIER {
                    pszObjId: PSTR::from_raw(szOID_RSA_SHA256RSA.as_ptr() as *mut u8),
                    ..Default::default()
                };

                (
                    CertCreateSelfSignCertificate(
                        None,
                        &subject_blob,
                        CERT_CREATE_SELFSIGN_FLAGS(0),
                        None,
                        Some(&signature_algorithm),
                        None,
                        None,
                        None,
                    ),
                    None,
                )
            };

            if cert_context.is_null() {
                Err(GetLastError().into())
            } else {
                Ok(Self {
                    cert_context,
                    key_handle,
                })
            }
        }
    }

    /// Get the DER-encoded bytes of the certificate.
    pub fn get_der_bytes(&self) -> Result<Vec<u8>, WinCryptoError> {
        unsafe {
            let cert_info = *self.cert_context;
            let der_bytes = std::slice::from_raw_parts(
                cert_info.pbCertEncoded,
                cert_info.cbCertEncoded as usize,
            );
            Ok(der_bytes.to_vec())
        }
    }

    #[allow(dead_code)]
    pub fn sha256_fingerprint(&self) -> Result<[u8; 32], WinCryptoError> {
        let der_bytes = self.get_der_bytes()?;
        crate::sys::sha256(&der_bytes)
    }

    #[cfg(any(test, not(feature = "prefer_dimpl")))]
    pub fn context(&self) -> *const CERT_CONTEXT {
        self.cert_context
    }

    /// Export the private key in PKCS#8 DER format.
    ///
    /// Only available when the certificate was created via `new_self_signed`
    /// with a key handle (EC-DSA keys).
    #[cfg(feature = "prefer_dimpl")]
    pub fn export_private_key_pkcs8_der(&self) -> Result<Vec<u8>, WinCryptoError> {
        use windows::Win32::Security::Cryptography::NCRYPT_PKCS8_PRIVATE_KEY_BLOB;
        use windows::Win32::Security::Cryptography::NCryptExportKey;
        let key_handle = self
            .key_handle
            .ok_or_else(|| WinCryptoError::Generic("No private key handle available".into()))?;

        // SAFETY: NCryptExportKey borrows the key handle and output buffer for
        // the duration of each call; both outlive this block.
        unsafe {
            // Query the required buffer size.
            let mut size = 0u32;
            NCryptExportKey(
                key_handle,
                None,
                NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                None,
                None,
                &mut size,
                NCRYPT_SILENT_FLAG,
            )?;

            let mut buf = vec![0u8; size as usize];
            NCryptExportKey(
                key_handle,
                None,
                NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                None,
                Some(&mut buf),
                &mut size,
                NCRYPT_SILENT_FLAG,
            )?;

            buf.truncate(size as usize);
            Ok(buf)
        }
    }
}

impl From<*const CERT_CONTEXT> for Certificate {
    fn from(cert_context: *const CERT_CONTEXT) -> Self {
        Self {
            cert_context,
            key_handle: None,
        }
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: The Certificate is no longer usable, so it's safe to pass the pointer
        // to Windows for release.
        unsafe {
            _ = CertFreeCertificateContext(Some(self.cert_context));
            if let Some(key_handle) = self.key_handle {
                _ = NCryptDeleteKey(key_handle, NCRYPT_SILENT_FLAG.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use windows::Win32::Security::Cryptography::CERT_X500_NAME_STR;
    use windows::Win32::Security::Cryptography::CertNameToStrA;
    use windows::Win32::Security::Cryptography::X509_ASN_ENCODING;
    use windows::Win32::Security::Cryptography::szOID_ECC_PUBLIC_KEY;
    use windows::Win32::Security::Cryptography::szOID_RSA_RSA;

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

#[cfg(all(test, feature = "prefer_dimpl"))]
mod dimpl_tests {
    #[test]
    fn export_pkcs8_ec_dsa() {
        let cert = super::Certificate::new_self_signed(true, "cn=WebRTC-PKCS8").unwrap();
        let pkcs8 = cert.export_private_key_pkcs8_der().unwrap();
        // PKCS#8 DER starts with a SEQUENCE tag (0x30).
        assert_eq!(pkcs8[0], 0x30);
        assert!(!pkcs8.is_empty());
    }

    #[test]
    fn export_pkcs8_no_key_handle() {
        let cert = super::Certificate::new_self_signed(false, "cn=WebRTC-RSA").unwrap();
        // RSA path doesn't store a key_handle, so export should fail.
        assert!(cert.export_private_key_pkcs8_der().is_err());
    }
}
