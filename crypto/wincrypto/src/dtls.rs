//! DTLS provider implementation using Windows SChannel.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};
use str0m_proto::crypto::dtls::{KeyingMaterial, SrtpProfile};
use str0m_proto::crypto::{CryptoError, DtlsVersion};

use crate::sys::{Certificate, Dtls, DtlsEvent};

/// Cache for Windows certificates, keyed by their DER bytes.
/// This ensures the same Windows certificate handle is used for both
/// fingerprint generation and DTLS handshake, even when multiple Rtc
/// instances are created in parallel.
static CERT_CACHE: LazyLock<Mutex<HashMap<Vec<u8>, Arc<Certificate>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug)]
pub(super) struct WinCryptoDtlsProvider;

impl DtlsProvider for WinCryptoDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        let cert = Certificate::new_self_signed(true, "CN=WebRTC").ok()?;
        let cert = Arc::new(cert);

        // Get the DER bytes from the certificate
        let der_bytes = cert.get_der_bytes().ok()?;

        // Cache the certificate for later use in new_dtls, keyed by DER bytes
        if let Ok(mut cache) = CERT_CACHE.lock() {
            cache.insert(der_bytes.clone(), Arc::clone(&cert));
        }

        Some(DtlsCert {
            certificate: der_bytes,
            private_key: vec![], // Private key is managed internally by Windows
        })
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
        // Look up the Windows certificate by its DER bytes
        let win_cert = CERT_CACHE
            .lock()
            .map_err(|e| CryptoError::Other(format!("Failed to lock certificate cache: {}", e)))?
            .get(&cert.certificate)
            .cloned()
            .ok_or_else(|| {
                CryptoError::Other(
                    "Certificate not found in cache - was generate_certificate called?".to_string(),
                )
            })?;

        let dtls =
            Dtls::new(win_cert).map_err(|e| CryptoError::Other(format!("DTLS creation: {}", e)))?;

        Ok(Box::new(WinCryptoDtlsInstance {
            dtls,
            pending_outputs: VecDeque::new(),
            queued_app_data: VecDeque::new(),
            last_timeout: None,
        }))
    }
}

// ============================================================================
// DTLS Instance Wrapper
// ============================================================================

struct WinCryptoDtlsInstance {
    dtls: Dtls,
    pending_outputs: VecDeque<PendingOutput>,
    /// Application data queued before handshake completes.
    queued_app_data: VecDeque<Vec<u8>>,
    /// The last time we were given via handle_timeout, used for calculating next timeout.
    last_timeout: Option<Instant>,
}

#[derive(Debug)]
enum PendingOutput {
    Connected,
    PeerCert(Vec<u8>),
    KeyingMaterial(KeyingMaterial, SrtpProfile),
    ApplicationData(Vec<u8>),
}

impl std::fmt::Debug for WinCryptoDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinCryptoDtlsInstance").finish()
    }
}

impl WinCryptoDtlsInstance {
    fn process_dtls_event(&mut self, event: DtlsEvent) {
        match event {
            DtlsEvent::Connected {
                srtp_profile_id,
                srtp_keying_material,
                peer_cert_der,
            } => {
                let profile = match srtp_profile_id {
                    0x0001 => SrtpProfile::AES128_CM_SHA1_80,
                    0x0007 => SrtpProfile::AEAD_AES_128_GCM,
                    0x0008 => SrtpProfile::AEAD_AES_256_GCM,
                    _ => return, // Unknown profile, ignore
                };

                // Queue up the sequence: Connected -> PeerCert -> KeyingMaterial
                self.pending_outputs.push_back(PendingOutput::Connected);
                self.pending_outputs
                    .push_back(PendingOutput::PeerCert(peer_cert_der));
                self.pending_outputs
                    .push_back(PendingOutput::KeyingMaterial(
                        KeyingMaterial::new(&srtp_keying_material),
                        profile,
                    ));
            }
            DtlsEvent::Data(data) => {
                self.pending_outputs
                    .push_back(PendingOutput::ApplicationData(data));
            }
            DtlsEvent::None | DtlsEvent::WouldBlock => {
                // No event to queue
            }
        }
    }

    /// Flush any application data queued before handshake completed.
    fn flush_queued_app_data(&mut self) -> Result<(), DtlsImplError> {
        while let Some(queued) = self.queued_app_data.pop_front() {
            let sent = self
                .dtls
                .send_data(&queued)
                .map_err(|e| DtlsImplError::CryptoError(format!("DTLS send: {}", e)))?;
            if !sent {
                // Handshake not complete yet, put data back
                self.queued_app_data.push_front(queued);
                break;
            }
        }
        Ok(())
    }
}

impl DtlsInstance for WinCryptoDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.dtls.set_as_client(active).expect("set_as_client");
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        let event = self
            .dtls
            .handle_receive(Some(packet))
            .map_err(|e| DtlsImplError::CryptoError(format!("DTLS error: {}", e)))?;

        // Store the event for poll_output to retrieve
        self.process_dtls_event(event);

        // If we just became connected, flush any queued application data
        if self.dtls.is_connected() {
            self.flush_queued_app_data()?;
        }

        Ok(())
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        // First check if we have pending outputs from a previous Connected event
        if let Some(pending) = self.pending_outputs.pop_front() {
            return match pending {
                PendingOutput::Connected => DtlsOutput::Connected,
                PendingOutput::PeerCert(cert) => {
                    let len = cert.len().min(buf.len());
                    buf[..len].copy_from_slice(&cert[..len]);
                    DtlsOutput::PeerCert(&buf[..len])
                }
                PendingOutput::KeyingMaterial(km, profile) => {
                    DtlsOutput::KeyingMaterial(km, profile)
                }
                PendingOutput::ApplicationData(data) => {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    DtlsOutput::ApplicationData(&buf[..len])
                }
            };
        }

        // Poll for datagram first
        if let Some(datagram) = self.dtls.pull_datagram() {
            let len = datagram.len().min(buf.len());
            buf[..len].copy_from_slice(&datagram[..len]);
            return DtlsOutput::Packet(&buf[..len]);
        }

        fn not_happening() -> Instant {
            Instant::now() + Duration::from_secs(3600 * 24 * 365 * 10)
        }

        // Return timeout based on last known time. If we don't have one yet,
        // return a far-future time until handle_timeout is called.
        let base_time = self.last_timeout.unwrap_or_else(not_happening);
        DtlsOutput::Timeout(base_time + std::time::Duration::from_millis(100))
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.last_timeout = Some(now);
        // SChannel handles DTLS retransmissions internally, so we don't need to do anything here.
        // The handshake is driven by handle_packet receiving data from the peer.
        Ok(())
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        // If handshake not complete, queue for later
        if !self.dtls.is_connected() {
            self.queued_app_data.push_back(data.to_vec());
            return Ok(());
        }

        // Flush any queued data first
        self.flush_queued_app_data()?;

        // Now send current data
        self.dtls
            .send_data(data)
            .map_err(|e| DtlsImplError::CryptoError(format!("DTLS send: {}", e)))?;
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.dtls.is_client().unwrap_or(false)
    }
}
