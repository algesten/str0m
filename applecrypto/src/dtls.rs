use super::{AppleCryptoError, Certificate};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

#[allow(dead_code)]
// The label used for SRTP key derivation from: https://datatracker.ietf.org/doc/html/rfc5764#section-4.2
const DTLS_KEY_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp\0";

#[allow(dead_code)]
// This size includes the encaptulation overhead of DTLS. So it must be larger than the MTU Str0m
// uses for SCTP.
const DATAGRAM_MTU: usize = 1200;

#[derive(Clone, Copy, Debug, PartialEq)]
enum EstablishmentState {
    Idle,
    #[allow(dead_code)]
    Handshaking,
    Established,
    #[allow(dead_code)]
    Failed,
}

pub enum DtlsEvent {
    None,
    WouldBlock,
    Connected {
        srtp_profile_id: u16,
        srtp_keying_material: Vec<u8>,
        peer_fingerprint: [u8; 32],
    },
    Data(Vec<u8>),
}

pub struct Dtls {
    _cert: Arc<Certificate>,
    is_client: Option<bool>,
    state: EstablishmentState,

    output_datagrams: VecDeque<Vec<u8>>,
}

impl Dtls {
    pub fn new(cert: Arc<Certificate>) -> Result<Self, AppleCryptoError> {
        Ok(Dtls {
            _cert: cert,
            is_client: None,
            state: EstablishmentState::Idle,
            output_datagrams: VecDeque::default(),
        })
    }

    pub fn is_client(&self) -> Option<bool> {
        self.is_client
    }

    pub fn is_connected(&self) -> bool {
        self.state == EstablishmentState::Established
    }

    pub fn set_as_client(&mut self, active: bool) -> Result<(), AppleCryptoError> {
        self.is_client = Some(active);

        todo!();
    }

    pub fn handle_receive(
        &mut self,
        datagram: Option<&[u8]>,
    ) -> Result<DtlsEvent, AppleCryptoError> {
        let state = self.state;
        match state {
            EstablishmentState::Established => {
                if let Some(datagram) = datagram {
                    self.process_packet(datagram)
                } else {
                    warn!("Unexpectedly asked to process no message!");
                    Ok(DtlsEvent::None)
                }
            }
            EstablishmentState::Handshaking => self.handshake(datagram),
            EstablishmentState::Failed => Err("Handshake failed".into()),
            EstablishmentState::Idle => Err("Handshake not initialized".into()),
        }
    }

    pub fn pull_datagram(&mut self) -> Option<Vec<u8>> {
        self.output_datagrams.pop_front()
    }

    pub fn next_timeout(&mut self, now: Instant) -> Option<Instant> {
        match self.state {
            EstablishmentState::Idle | EstablishmentState::Handshaking => {
                Some(now + Duration::from_millis(500))
            }
            _ => None,
        }
    }

    // This is DATA sent from client over SCTP/DTLS
    pub fn send_data(&mut self, _data: &[u8]) -> Result<bool, AppleCryptoError> {
        if self.state != EstablishmentState::Established {
            return Ok(false);
        }
        todo!();
    }

    fn handshake(&mut self, _datagram: Option<&[u8]>) -> Result<DtlsEvent, AppleCryptoError> {
        let Some(_is_client) = self.is_client else {
            return Err("handshake attempted without setting is_client".into());
        };
        todo!();
    }

    fn process_packet(&mut self, _datagram: &[u8]) -> Result<DtlsEvent, AppleCryptoError> {
        if self.state != EstablishmentState::Established {
            return Ok(DtlsEvent::WouldBlock);
        }
        todo!();
    }
}

impl Drop for Dtls {
    fn drop(&mut self) {
        todo!();
    }
}

fn _srtp_keying_material_len(srtp_profile_id: u16) -> Result<u32, AppleCryptoError> {
    match srtp_profile_id {
        0x0001 => Ok(16 * 2 + 14 * 2),
        0x0007 => Ok(16 * 2 + 12 * 2),
        0x0008 => Ok(32 * 2 + 12 * 2),
        id => Err(format!("Unknown SRTP Profile Requested: {id}").into()),
    }
}
