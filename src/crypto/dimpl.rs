use std::collections::VecDeque;
use std::time::Instant;

use dimpl::certificate::calculate_fingerprint;
use dimpl::{Config, Output};

use crate::crypto::dtls::DtlsInner;
use crate::crypto::{Fingerprint, KeyingMaterial, SrtpProfile};
use crate::io::DatagramSend;
use crate::util::already_happened;

use super::{CryptoError, DtlsEvent};

pub struct DimplImpl {
    instance: dimpl::Dtls,
    inited: bool,
    connected: bool,
    poll_buffer: Vec<u8>,
    last_now: Instant,
    timeout: Option<Instant>,
    events: VecDeque<DtlsEvent>,
    to_send: VecDeque<DatagramSend>,
    delayed_error: Option<dimpl::Error>,
}

impl DimplImpl {
    pub fn new(cert: &[u8], key: &[u8]) -> Result<Self, CryptoError> {
        let config = std::sync::Arc::new(Config::default());

        Ok(Self {
            instance: dimpl::Dtls::new(config, cert.to_vec(), key.to_vec()),
            inited: false,
            connected: false,
            poll_buffer: vec![0; 2000], // MTU should cap this
            last_now: already_happened(),
            timeout: None,
            events: VecDeque::new(),
            to_send: VecDeque::new(),
            delayed_error: None,
        })
    }

    fn poll_instance(&mut self) {
        // The dimpl instance must get a handle_timeout before poll_output will work.
        if self.last_now == already_happened() {
            return;
        }

        loop {
            match self.instance.poll_output(&mut self.poll_buffer) {
                Output::Packet(items) => self.to_send.push_back(items.to_vec().into()),
                Output::Timeout(instant) => {
                    // Timeout means there is no more state coming from the instance
                    self.timeout = Some(instant);
                    break;
                }
                Output::Connected => {
                    self.connected = true;
                    self.events.push_back(DtlsEvent::Connected);
                }
                Output::PeerCert(items) => {
                    let bytes = calculate_fingerprint(items);
                    let fingerprint = Fingerprint {
                        hash_func: "sha-256".into(),
                        bytes,
                    };
                    self.events
                        .push_back(DtlsEvent::RemoteFingerprint(fingerprint));
                }
                Output::KeyingMaterial(mat, prof) => self.events.push_back(
                    DtlsEvent::SrtpKeyingMaterial(KeyingMaterial::new(mat.to_vec()), prof.into()),
                ),
                Output::ApplicationData(items) => {
                    self.events.push_back(DtlsEvent::Data(items.to_vec()))
                }
            }
        }
    }

    fn surface_error(&mut self) -> Result<(), CryptoError> {
        if let Some(err) = self.delayed_error.take() {
            return Err(err.into());
        }
        Ok(())
    }
}

impl From<dimpl::SrtpProfile> for SrtpProfile {
    fn from(prof: dimpl::SrtpProfile) -> Self {
        match prof {
            dimpl::SrtpProfile::Aes128CmSha1_80 => SrtpProfile::Aes128CmSha1_80,
            dimpl::SrtpProfile::AeadAes128Gcm => SrtpProfile::AeadAes128Gcm,
            dimpl::SrtpProfile::AeadAes256Gcm => SrtpProfile::AeadAes256Gcm,
        }
    }
}

impl DtlsInner for DimplImpl {
    fn is_active(&self) -> Option<bool> {
        if !self.inited {
            return None;
        }
        Some(self.instance.is_active())
    }

    fn set_active(&mut self, active: bool) -> Result<(), CryptoError> {
        self.inited = true;
        self.instance.set_active(active);
        Ok(())
    }

    fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        // Dimpl can't handle the "already_happened" in the past distant.
        // It only wants "real" now.
        if now == already_happened() {
            return None;
        }

        self.last_now = now;

        if let Err(err) = self.instance.handle_timeout(now) {
            self.delayed_error = Some(err);
        }

        // This should eventually set the self.timeout.
        self.poll_instance();

        self.timeout.take()
    }

    fn handle_handshake(&mut self, o: &mut VecDeque<DtlsEvent>) -> Result<bool, CryptoError> {
        self.surface_error()?;
        o.extend(self.events.drain(..));
        Ok(!self.connected)
    }

    fn handle_receive(
        &mut self,
        packet: &[u8],
        o: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        self.surface_error()?;

        self.instance.handle_packet(packet)?;
        self.poll_instance();

        self.surface_error()?;
        o.extend(self.events.drain(..));

        Ok(())
    }

    fn poll_datagram(&mut self) -> Option<DatagramSend> {
        self.to_send.pop_front()
    }

    fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.surface_error()?;

        self.instance.send_application_data(data)?;

        // After sending data, we need to poll to ensure poll_datagram() will
        // get the next encrypted datagram.
        self.poll_instance();

        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}
