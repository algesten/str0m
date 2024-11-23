use std::collections::VecDeque;
use std::time::Instant;

use crate::crypto::dtls::DtlsInner;
use crate::crypto::CryptoError;
use crate::crypto::DtlsEvent;
use crate::crypto::{KeyingMaterial, SrtpProfile};
use crate::io::DATAGRAM_MTU_WARN;

use super::cert::{create_sha256_fingerprint, WinCryptoDtlsCert};
use str0m_wincrypto::{WinCryptoDtls, WinCryptoDtlsEvent};

pub struct WinCryptoDtlsImpl(WinCryptoDtls);

impl WinCryptoDtlsImpl {
    pub fn new(cert: WinCryptoDtlsCert) -> Result<Self, super::CryptoError> {
        Ok(WinCryptoDtlsImpl(WinCryptoDtls::new(
            cert.certificate.clone(),
        )?))
    }
}

impl DtlsInner for WinCryptoDtlsImpl {
    fn set_active(&mut self, active: bool) {
        self.0.set_as_client(active);
    }

    fn is_active(&self) -> Option<bool> {
        self.0.is_client()
    }

    fn is_connected(&self) -> bool {
        self.0.is_connected()
    }

    fn handle_receive(
        &mut self,
        datagram: &[u8],
        output_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        transform_dtls_event(self.0.handle_receive(Some(datagram))?, output_events);
        Ok(())
    }

    fn handle_handshake(
        &mut self,
        output_events: &mut VecDeque<DtlsEvent>,
    ) -> Result<bool, CryptoError> {
        if self.is_connected() || self.is_active().is_none() {
            return Ok(false);
        }
        transform_dtls_event(self.0.handle_receive(None)?, output_events);
        Ok(!self.0.is_connected())
    }

    // This is DATA sent from client over SCTP/DTLS
    fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self.0.send_data(data) {
            Ok(true) => Ok(()),
            Ok(false) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Not ready".to_string(),
            )
            .into()),
            Err(e) => Err(e.into()),
        }
    }

    fn poll_datagram(&mut self) -> Option<crate::net::DatagramSend> {
        let x: Option<crate::io::DatagramSend> = self.0.pull_datagram().map(|v| v.into());
        if let Some(x) = &x {
            if x.len() > DATAGRAM_MTU_WARN {
                warn!("DTLS above MTU {}: {}", DATAGRAM_MTU_WARN, x.len());
            }
            trace!("Poll datagram: {}", x.len());
        }
        x
    }

    fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        self.0.next_timeout(now)
    }
}

fn srtp_profile_from_network_endian_id(srtp_profile_id: u16) -> SrtpProfile {
    match srtp_profile_id {
        0x0001 => SrtpProfile::Aes128CmSha1_80,
        0x0007 => SrtpProfile::AeadAes128Gcm,
        _ => panic!("Unknown SRTP profile ID: {:04x}", srtp_profile_id),
    }
}

fn transform_dtls_event(event: WinCryptoDtlsEvent, output_events: &mut VecDeque<DtlsEvent>) {
    match event {
        WinCryptoDtlsEvent::None => {}
        WinCryptoDtlsEvent::WouldBlock => {}
        WinCryptoDtlsEvent::Connected {
            srtp_profile_id,
            srtp_keying_material,
            peer_fingerprint,
        } => {
            output_events.push_back(DtlsEvent::Connected);
            output_events.push_back(DtlsEvent::RemoteFingerprint(create_sha256_fingerprint(
                &peer_fingerprint,
            )));
            output_events.push_back(DtlsEvent::SrtpKeyingMaterial(
                KeyingMaterial::new(srtp_keying_material),
                srtp_profile_from_network_endian_id(srtp_profile_id),
            ));
        }
        WinCryptoDtlsEvent::Data(vec) => output_events.push_back(DtlsEvent::Data(vec)),
    }
}
