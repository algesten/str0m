#![allow(unreachable_patterns, dead_code, unused_variables)]

use std::collections::VecDeque;
use std::fmt;
use std::time::Instant;

use crate::net::DatagramSend;

use super::{CryptoError, Fingerprint, KeyingMaterial, SrtpProfile};

// libWebRTC says "WebRTC" here when doing OpenSSL, for BoringSSL they seem
// to generate a random 8 characters.
// https://webrtc.googlesource.com/src/+/1568f1b1330f94494197696fe235094e6293b258/rtc_base/rtc_certificate_generator.cc#27
//
// Pion also sets this to "WebRTC", maybe for compatibility reasons.
// https://github.com/pion/webrtc/blob/eed2bb2d3b9f204f9de1cd7e1046ca5d652778d2/constants.go#L31
pub const DTLS_CERT_IDENTITY: &str = "WebRTC";

/// Events arising from a [`Dtls`] instance.
pub enum DtlsEvent {
    /// When the DTLS has finished handshaking.
    Connected,

    /// Keying material for SRTP encryption master key and the selected SRTP profile.
    SrtpKeyingMaterial(KeyingMaterial, SrtpProfile),

    /// The fingerprint of the remote peer.
    ///
    /// This should be checked against the fingerprint communicated in the SDP.
    RemoteFingerprint(Fingerprint),

    /// Decrypted data from incoming DTLS traffic.
    Data(Vec<u8>),
}

/// Certificate used for DTLS.
#[derive(Clone)]
pub struct DtlsCert(super::_impl::Cert);

impl DtlsCert {
    /// Creates a new Dtls certificate.
    pub fn new() -> Self {
        DtlsCert(super::_impl::Cert::new())
    }

    /// Creates a fingerprint for this certificate.
    ///
    /// Fingerprints are used to verify a remote peer's certificate.
    pub fn fingerprint(&self) -> Fingerprint {
        self.0.fingerprint()
    }

    pub(crate) fn create_dtls_impl(&self) -> Result<DtlsImpl, CryptoError> {
        let dtls = super::_impl::Dtls::new(self.0.clone())?;

        Ok(DtlsImpl(dtls))
    }
}

impl fmt::Debug for DtlsCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub struct DtlsImpl(super::_impl::Dtls);

impl DtlsImpl {
    pub fn set_active(&mut self, active: bool) {
        self.0.set_active(active);
    }

    pub fn handle_handshake(&mut self, o: &mut VecDeque<DtlsEvent>) -> Result<bool, CryptoError> {
        self.0.handle_handshake(o)
    }

    pub fn is_active(&self) -> Option<bool> {
        self.0.is_active()
    }

    pub fn handle_receive(
        &mut self,
        m: &[u8],
        o: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        self.0.handle_receive(m, o)
    }

    pub fn poll_datagram(&mut self) -> Option<DatagramSend> {
        self.0.poll_datagram()
    }

    pub fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        self.0.poll_timeout(now)
    }

    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.handle_input(data)
    }

    pub fn is_connected(&self) -> bool {
        self.0.is_connected()
    }
}
