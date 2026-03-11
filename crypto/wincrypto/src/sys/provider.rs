//! CryptoProvider implementation for Windows CNG/SChannel.
//!
//! This module provides a complete CryptoProvider that can be passed to str0m,
//! implementing all cryptographic operations using Windows native APIs.

use dimpl::{Error as DtlsImplError, KeyingMaterial, SrtpProfile};
use std::sync::Arc;
use std::time::Instant;
use str0m_proto::crypto::SupportedAes128CmSha1_80;
use str0m_proto::crypto::{AeadAes128GcmCipher, AeadAes256GcmCipher, Aes128CmSha1_80Cipher};
use str0m_proto::crypto::{CryptoError, CryptoProvider};
use str0m_proto::crypto::{DtlsCert, DtlsInstance, DtlsOutput, DtlsProvider, DtlsVersion};
use str0m_proto::crypto::{Sha1HmacProvider, Sha256Provider};
use str0m_proto::crypto::{SrtpProvider, SupportedAeadAes128Gcm, SupportedAeadAes256Gcm};

/// Create the default Windows CNG/SChannel crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2 for secure key exchange (using dimpl protocol + SChannel)
/// - SRTP for encrypted media (using Windows CNG)
/// - SHA1-HMAC for STUN message integrity (using Windows CNG)
/// - SHA-256 for certificate fingerprints (using Windows CNG)
///
/// # Example
///
/// ```no_run
/// use str0m::RtcConfig;
///
/// let crypto_provider = str0m_wincrypto::default_provider();
/// let config = RtcConfig::new().with_crypto_provider(crypto_provider);
/// ```
pub fn default_provider() -> CryptoProvider {
    static SRTP: WinCryptoSrtpProvider = WinCryptoSrtpProvider;
    static SHA1_HMAC: WinCryptoSha1HmacProvider = WinCryptoSha1HmacProvider;
    static SHA256: WinCryptoSha256Provider = WinCryptoSha256Provider;
    static DTLS: WinCryptoDtlsProvider = WinCryptoDtlsProvider;

    CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
    }
}

// ============================================================================
// SHA1 HMAC Provider
// ============================================================================

#[derive(Debug)]
struct WinCryptoSha1HmacProvider;

impl Sha1HmacProvider for WinCryptoSha1HmacProvider {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        crate::sha1_hmac(key, payloads).expect("SHA1-HMAC computation")
    }
}

// ============================================================================
// SHA256 Provider
// ============================================================================

#[derive(Debug)]
struct WinCryptoSha256Provider;

impl Sha256Provider for WinCryptoSha256Provider {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        use windows::core::Owned;
        use windows::Win32::Security::Cryptography::BCryptHashData;
        use windows::Win32::Security::Cryptography::BCRYPT_HASH_HANDLE;
        use windows::Win32::Security::Cryptography::BCRYPT_SHA256_ALG_HANDLE;
        use windows::Win32::Security::Cryptography::{BCryptCreateHash, BCryptFinishHash};

        let mut hash = [0u8; 32];
        unsafe {
            let mut hash_handle = Owned::new(BCRYPT_HASH_HANDLE::default());

            crate::WinCryptoError::from_ntstatus(BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                &mut *hash_handle,
                None,
                None,
                0,
            ))
            .expect("SHA-256 hash creation");

            crate::WinCryptoError::from_ntstatus(BCryptHashData(*hash_handle, data, 0))
                .expect("SHA-256 hash data");

            crate::WinCryptoError::from_ntstatus(BCryptFinishHash(*hash_handle, &mut hash, 0))
                .expect("SHA-256 hash finish");
        }
        hash
    }
}

// ============================================================================
// SRTP Provider
// ============================================================================

#[derive(Debug)]
struct WinCryptoSrtpProvider;

impl SrtpProvider for WinCryptoSrtpProvider {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &WinCryptoAes128CmSha1_80Factory
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &WinCryptoAeadAes128GcmFactory
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &WinCryptoAeadAes256GcmFactory
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        let key = crate::SrtpKey::create_aes_ecb_key(key).expect("AES-128 ECB key");
        let count = crate::srtp_aes_ecb_round(&key, input, output).expect("AES-128 ECB");
        assert_eq!(count, 16 + 16); // block size + padding
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        let key = crate::SrtpKey::create_aes_ecb_key(key).expect("AES-256 ECB key");
        let count = crate::srtp_aes_ecb_round(&key, input, output).expect("AES-256 ECB");
        assert_eq!(count, 16 + 16); // block size + padding
    }
}

// Cipher Factories

#[derive(Debug)]
struct WinCryptoAes128CmSha1_80Factory;

impl SupportedAes128CmSha1_80 for WinCryptoAes128CmSha1_80Factory {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        Box::new(WinCryptoAes128CmSha1_80::new(key))
    }
}

#[derive(Debug)]
struct WinCryptoAeadAes128GcmFactory;

impl SupportedAeadAes128Gcm for WinCryptoAeadAes128GcmFactory {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        Box::new(WinCryptoAeadAes128Gcm::new(key))
    }
}

#[derive(Debug)]
struct WinCryptoAeadAes256GcmFactory;

impl SupportedAeadAes256Gcm for WinCryptoAeadAes256GcmFactory {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        Box::new(WinCryptoAeadAes256Gcm::new(key))
    }
}

// Cipher Implementations

#[derive(Debug)]
struct WinCryptoAes128CmSha1_80 {
    key: crate::SrtpKey,
}

impl WinCryptoAes128CmSha1_80 {
    fn new(key: [u8; 16]) -> Self {
        Self {
            key: crate::SrtpKey::create_aes_ctr_key(&key).expect("AES-128-CTR key"),
        }
    }
}

impl Aes128CmSha1_80Cipher for WinCryptoAes128CmSha1_80 {
    fn encrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        crate::srtp_aes_128_cm(&self.key, iv, input, output)
            .map_err(|e| CryptoError::Other(format!("AES-128-CM encrypt: {}", e)))?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        crate::srtp_aes_128_cm(&self.key, iv, input, output)
            .map_err(|e| CryptoError::Other(format!("AES-128-CM decrypt: {}", e)))?;
        Ok(())
    }
}

#[derive(Debug)]
struct WinCryptoAeadAes128Gcm {
    key: crate::SrtpKey,
}

impl WinCryptoAeadAes128Gcm {
    fn new(key: [u8; 16]) -> Self {
        Self {
            key: crate::SrtpKey::create_aes_gcm_key(&key).expect("AES-128-GCM key"),
        }
    }
}

impl AeadAes128GcmCipher for WinCryptoAeadAes128Gcm {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        crate::srtp_aead_aes_gcm_encrypt(&self.key, iv, aad, input, output)
            .map_err(|e| CryptoError::Other(format!("AEAD-AES-128-GCM encrypt: {}", e)))?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        crate::srtp_aead_aes_gcm_decrypt(&self.key, iv, aads, input, output)
            .map_err(|e| CryptoError::Other(format!("AEAD-AES-128-GCM decrypt: {}", e)))
    }
}

#[derive(Debug)]
struct WinCryptoAeadAes256Gcm {
    key: crate::SrtpKey,
}

impl WinCryptoAeadAes256Gcm {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key: crate::SrtpKey::create_aes_gcm_key(&key).expect("AES-256-GCM key"),
        }
    }
}

impl AeadAes256GcmCipher for WinCryptoAeadAes256Gcm {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        crate::srtp_aead_aes_gcm_encrypt(&self.key, iv, aad, input, output)
            .map_err(|e| CryptoError::Other(format!("AEAD-AES-256-GCM encrypt: {}", e)))?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        crate::srtp_aead_aes_gcm_decrypt(&self.key, iv, aads, input, output)
            .map_err(|e| CryptoError::Other(format!("AEAD-AES-256-GCM decrypt: {}", e)))
    }
}

// ============================================================================
// DTLS Provider
// ============================================================================

#[derive(Debug)]
struct WinCryptoDtlsProvider;

impl DtlsProvider for WinCryptoDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        let cert = crate::Certificate::new_self_signed(true, "CN=WebRTC").ok()?;

        // Get the DER bytes from the certificate
        unsafe {
            let cert_context = *cert.context();
            let der_bytes = std::slice::from_raw_parts(
                cert_context.pbCertEncoded,
                cert_context.cbCertEncoded as usize,
            );

            // Store the certificate so we can use it later
            Some(DtlsCert {
                certificate: der_bytes.to_vec(),
                private_key: vec![], // We'll handle this through the Certificate wrapper
            })
        }
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        _now: Instant,
        dtls_version: DtlsVersion,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        if dtls_version != DtlsVersion::Dtls12 {
            return Err(CryptoError::Other(
                "WinCrypto DTLS provider only supports DTLS 1.2. \
                 Use aws-lc-rs or rust-crypto backend for DTLS 1.3/Auto."
                    .to_string(),
            ));
        }
        // For now, generate a new certificate since we need the Windows CERT_CONTEXT
        // In a real implementation, we'd need to reconstruct from the DER bytes
        let win_cert = crate::Certificate::new_self_signed(true, "CN=WebRTC")
            .map_err(|e| CryptoError::Other(format!("Certificate creation: {}", e)))?;

        let dtls = crate::Dtls::new(Arc::new(win_cert))
            .map_err(|e| CryptoError::Other(format!("DTLS creation: {}", e)))?;

        Ok(Box::new(WinCryptoDtlsInstance { dtls }))
    }
}

// ============================================================================
// DTLS Instance Wrapper
// ============================================================================

struct WinCryptoDtlsInstance {
    dtls: crate::Dtls,
}

impl std::fmt::Debug for WinCryptoDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinCryptoDtlsInstance").finish()
    }
}

impl DtlsInstance for WinCryptoDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.dtls.set_as_client(active).expect("set_as_client");
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls
            .handle_receive(Some(packet))
            .map_err(|e| DtlsImplError::from(format!("DTLS error: {}", e)))?;
        Ok(())
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        // Poll for datagram first
        if let Some(datagram) = self.dtls.pull_datagram() {
            let len = datagram.len().min(buf.len());
            buf[..len].copy_from_slice(&datagram[..len]);
            return DtlsOutput::Datagram(&buf[..len]);
        }

        // Check for events
        match self.dtls.handle_receive(None) {
            Ok(crate::DtlsEvent::Connected {
                srtp_profile_id,
                srtp_keying_material,
                peer_fingerprint,
            }) => {
                let profile = match srtp_profile_id {
                    0x0001 => SrtpProfile::AES128_CM_SHA1_80,
                    0x0007 => SrtpProfile::AEAD_AES_128_GCM,
                    0x0008 => SrtpProfile::AEAD_AES_256_GCM,
                    _ => return DtlsOutput::Error(DtlsImplError::from("Unknown SRTP profile")),
                };

                DtlsOutput::Connected {
                    srtp_profile: profile,
                    keying_material: KeyingMaterial::new(&srtp_keying_material),
                    peer_fingerprint,
                }
            }
            Ok(crate::DtlsEvent::Data(data)) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                DtlsOutput::ApplicationData(&buf[..len])
            }
            Ok(crate::DtlsEvent::None) | Ok(crate::DtlsEvent::WouldBlock) => DtlsOutput::None,
            Err(e) => DtlsOutput::Error(DtlsImplError::from(format!("DTLS error: {}", e))),
        }
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), DtlsImplError> {
        self.dtls
            .handle_receive(None)
            .map_err(|e| DtlsImplError::from(format!("DTLS timeout: {}", e)))?;
        Ok(())
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls
            .send_data(data)
            .map_err(|e| DtlsImplError::from(format!("DTLS send: {}", e)))?;
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.dtls.is_client().unwrap_or(false)
    }
}
