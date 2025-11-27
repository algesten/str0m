//! DTLS provider implementation using Windows SChannel.

use crate::crypto::{CryptoError, DtlsCert, DtlsInstance, DtlsOutput, DtlsProvider};
use crate::crypto::{KeyingMaterial, SrtpProfile};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug)]
pub(super) struct WinCryptoDtlsProvider;

impl DtlsProvider for WinCryptoDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        let cert = str0m_wincrypto::Certificate::new_self_signed(true, "CN=WebRTC").ok()?;

        // Get the DER bytes and fingerprint from the certificate
        let der_bytes = cert.get_der_bytes().ok()?;

        Some(DtlsCert {
            certificate: der_bytes,
            private_key: vec![], // Private key is managed internally by Windows
        })
    }

    fn new_dtls(&self, _cert: &DtlsCert) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        // For now, generate a new certificate since we need the Windows CERT_CONTEXT
        // In a real implementation, we'd need to reconstruct from the DER bytes
        let win_cert = str0m_wincrypto::Certificate::new_self_signed(true, "CN=WebRTC")
            .map_err(|e| CryptoError::Other(format!("Certificate creation: {}", e)))?;

        let dtls = str0m_wincrypto::Dtls::new(Arc::new(win_cert))
            .map_err(|e| CryptoError::Other(format!("DTLS creation: {}", e)))?;

        Ok(Box::new(WinCryptoDtlsInstance {
            dtls,
            pending_outputs: VecDeque::new(),
        }))
    }
}

// ============================================================================
// DTLS Instance Wrapper
// ============================================================================

struct WinCryptoDtlsInstance {
    dtls: str0m_wincrypto::Dtls,
    pending_outputs: VecDeque<PendingOutput>,
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
    fn process_dtls_event(&mut self, event: str0m_wincrypto::DtlsEvent) {
        match event {
            str0m_wincrypto::DtlsEvent::Connected {
                srtp_profile_id,
                srtp_keying_material,
                peer_fingerprint,
            } => {
                let profile = match srtp_profile_id {
                    0x0001 => SrtpProfile::Aes128CmSha1_80,
                    0x0007 => SrtpProfile::AeadAes128Gcm,
                    0x0008 => SrtpProfile::AeadAes256Gcm,
                    _ => return, // Unknown profile, ignore
                };

                // Queue up the sequence: Connected -> PeerCert -> KeyingMaterial
                self.pending_outputs.push_back(PendingOutput::Connected);
                self.pending_outputs
                    .push_back(PendingOutput::PeerCert(peer_fingerprint.to_vec()));
                self.pending_outputs
                    .push_back(PendingOutput::KeyingMaterial(
                        KeyingMaterial::new(&srtp_keying_material),
                        profile,
                    ));
            }
            str0m_wincrypto::DtlsEvent::Data(data) => {
                self.pending_outputs
                    .push_back(PendingOutput::ApplicationData(data));
            }
            str0m_wincrypto::DtlsEvent::None | str0m_wincrypto::DtlsEvent::WouldBlock => {
                // No event to queue
            }
        }
    }
}

impl DtlsInstance for WinCryptoDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.dtls.set_as_client(active).expect("set_as_client");
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), crate::crypto::DimplError> {
        let event = self
            .dtls
            .handle_receive(Some(packet))
            .map_err(|e| crate::crypto::DimplError::CryptoError(format!("DTLS error: {}", e)))?;

        // Store the event for poll_output to retrieve
        self.process_dtls_event(event);
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

        // Return timeout - actual handshake progression happens in handle_timeout
        DtlsOutput::Timeout(Instant::now() + std::time::Duration::from_millis(100))
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), crate::crypto::DimplError> {
        // For wincrypto, we don't call handle_receive(None) from handle_timeout.
        // The handshake progresses via handle_packet when packets arrive.
        // This is different from dimpl which uses handle_timeout for retransmissions.
        Ok(())
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), crate::crypto::DimplError> {
        self.dtls
            .send_data(data)
            .map_err(|e| crate::crypto::DimplError::CryptoError(format!("DTLS send: {}", e)))?;
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.dtls.is_client().unwrap_or(false)
    }
}
