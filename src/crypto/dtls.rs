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
pub struct DtlsCert(DtlsCertInner);

#[derive(Debug, Clone)]
enum DtlsCertInner {
    #[cfg(feature = "openssl")]
    OpenSsl(super::ossl::OsslDtlsCert),
    #[cfg(feature = "wincrypto")]
    WinCrypto(super::wincrypto::WinCryptoDtlsCert),
}

impl DtlsCert {
    #[cfg(feature = "openssl")]
    /// Create a new OpenSSL variant of the certificate.
    pub fn new_openssl() -> Self {
        let cert = super::ossl::OsslDtlsCert::new();
        DtlsCert(DtlsCertInner::OpenSsl(cert))
    }

    #[cfg(feature = "wincrypto")]
    /// Create a new Windows Crypto variant of the certificate.
    pub fn new_wincrypto() -> Self {
        let cert = super::wincrypto::WinCryptoDtlsCert::new();
        DtlsCert(DtlsCertInner::WinCrypto(cert))
    }

    /// Creates a fingerprint for this certificate.
    ///
    /// Fingerprints are used to verify a remote peer's certificate.
    pub fn fingerprint(&self) -> Fingerprint {
        match &self.0 {
            #[cfg(feature = "openssl")]
            DtlsCertInner::OpenSsl(v) => v.fingerprint(),
            #[cfg(feature = "wincrypto")]
            DtlsCertInner::WinCrypto(v) => v.fingerprint(),
            _ => unreachable!(),
        }
    }

    pub(crate) fn create_dtls_impl(&self) -> Result<DtlsImpl, CryptoError> {
        match &self.0 {
            #[cfg(feature = "openssl")]
            DtlsCertInner::OpenSsl(c) => Ok(DtlsImpl::OpenSsl(super::ossl::OsslDtlsImpl::new(
                c.clone(),
            )?)),
            #[cfg(feature = "wincrypto")]
            DtlsCertInner::WinCrypto(c) => Ok(DtlsImpl::WinCrypto(
                super::wincrypto::WinCryptoDtlsImpl::new(c.clone())?,
            )),
            _ => unreachable!(),
        }
    }
}

impl fmt::Debug for DtlsCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            #[cfg(feature = "openssl")]
            DtlsCertInner::OpenSsl(c) => c.fmt(f),
            #[cfg(feature = "wincrypto")]
            DtlsCertInner::WinCrypto(c) => c.fmt(f),
            _ => unreachable!(),
        }
    }
}

pub trait DtlsInner: Sized {
    /// Set whether this instance is active or passive.
    ///
    /// i.e. initiating the client hello or not. This must be called
    /// exactly once before starting to handshake (I/O).
    fn set_active(&mut self, active: bool);

    /// Handle the handshake. Once this succeeds, it becomes a no-op.
    fn handle_handshake(&mut self, o: &mut VecDeque<DtlsEvent>) -> Result<bool, CryptoError>;

    /// If set_active, returns what was set.
    fn is_active(&self) -> Option<bool>;

    /// Handles an incoming DTLS datagrams.
    fn handle_receive(&mut self, m: &[u8], o: &mut VecDeque<DtlsEvent>) -> Result<(), CryptoError>;

    /// Poll for the next datagram to send.
    fn poll_datagram(&mut self) -> Option<DatagramSend>;

    /// Poll for next timeout. This is only used during DTLS handshake.
    fn poll_timeout(&mut self, now: Instant) -> Option<Instant>;

    /// Handling incoming data to be sent as DTLS datagrams.
    fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Whether the DTLS connection is established.
    fn is_connected(&self) -> bool;
}

pub enum DtlsImpl {
    #[cfg(feature = "openssl")]
    OpenSsl(super::ossl::OsslDtlsImpl),
    #[cfg(feature = "wincrypto")]
    WinCrypto(super::wincrypto::WinCryptoDtlsImpl),
}

impl DtlsImpl {
    pub fn set_active(&mut self, active: bool) {
        match self {
            #[cfg(feature = "openssl")]
            DtlsImpl::OpenSsl(i) => i.set_active(active),
            #[cfg(feature = "wincrypto")]
            DtlsImpl::WinCrypto(i) => i.set_active(active),
            _ => unreachable!(),
        }
    }

    pub fn handle_handshake(&mut self, o: &mut VecDeque<DtlsEvent>) -> Result<bool, CryptoError> {
        match self {
            #[cfg(feature = "openssl")]
            DtlsImpl::OpenSsl(i) => i.handle_handshake(o),
            #[cfg(feature = "wincrypto")]
            DtlsImpl::WinCrypto(i) => i.handle_handshake(o),
            _ => unreachable!(),
        }
    }

    pub fn is_active(&self) -> Option<bool> {
        match self {
            #[cfg(feature = "openssl")]
            DtlsImpl::OpenSsl(i) => i.is_active(),
            #[cfg(feature = "wincrypto")]
            DtlsImpl::WinCrypto(i) => i.is_active(),
            _ => unreachable!(),
        }
    }

    pub fn handle_receive(
        &mut self,
        m: &[u8],
        o: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "openssl")]
            DtlsImpl::OpenSsl(i) => i.handle_receive(m, o),
            #[cfg(feature = "wincrypto")]
            DtlsImpl::WinCrypto(i) => i.handle_receive(m, o),
            _ => unreachable!(),
        }
    }

    pub fn poll_datagram(&mut self) -> Option<DatagramSend> {
        match self {
            #[cfg(feature = "openssl")]
            DtlsImpl::OpenSsl(i) => i.poll_datagram(),
            #[cfg(feature = "wincrypto")]
            DtlsImpl::WinCrypto(i) => i.poll_datagram(),
            _ => unreachable!(),
        }
    }

    pub fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        match self {
            #[cfg(feature = "openssl")]
            DtlsImpl::OpenSsl(i) => i.poll_timeout(now),
            #[cfg(feature = "wincrypto")]
            DtlsImpl::WinCrypto(i) => i.poll_timeout(now),
            _ => unreachable!(),
        }
    }

    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "openssl")]
            DtlsImpl::OpenSsl(i) => i.handle_input(data),
            #[cfg(feature = "wincrypto")]
            DtlsImpl::WinCrypto(i) => i.handle_input(data),
            _ => unreachable!(),
        }
    }

    pub fn is_connected(&self) -> bool {
        match self {
            #[cfg(feature = "openssl")]
            DtlsImpl::OpenSsl(i) => i.is_connected(),
            #[cfg(feature = "wincrypto")]
            DtlsImpl::WinCrypto(i) => i.is_connected(),
            _ => unreachable!(),
        }
    }
}
