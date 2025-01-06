#![allow(unreachable_patterns, dead_code, unused_variables)]

use std::collections::VecDeque;
use std::fmt;
use std::time::Instant;

use crate::net::DatagramSend;

use super::CryptoProvider;
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
    #[cfg(not(feature = "openssl"))]
    OpenSsl(DummyCert),
    #[cfg(all(feature = "wincrypto", target_os = "windows"))]
    WinCrypto(super::wincrypto::WinCryptoDtlsCert),
    #[cfg(not(all(feature = "wincrypto", target_os = "windows")))]
    WinCrypto(DummyCert),
}

impl DtlsCert {
    /// Creates a new DTLS certificate.
    ///
    /// The certificate is bound to an actual crypto implementation. Pass the
    /// desired provider. The provider implementations will need turning on
    /// using the feature flags:
    ///
    /// * **openssl** (defaults to on) for crypto backed by OpenSSL.
    /// * **wincrypto** for crypto backed by windows crypto.
    pub fn new(p: CryptoProvider) -> Self {
        let inner = match p {
            CryptoProvider::OpenSsl => {
                #[cfg(feature = "openssl")]
                {
                    let cert = super::ossl::OsslDtlsCert::new();
                    DtlsCertInner::OpenSsl(cert)
                }
                #[cfg(not(feature = "openssl"))]
                {
                    DtlsCertInner::OpenSsl(DummyCert(p))
                }
            }
            CryptoProvider::WinCrypto => {
                #[cfg(all(feature = "wincrypto", target_os = "windows"))]
                {
                    let cert = super::wincrypto::WinCryptoDtlsCert::new();
                    DtlsCertInner::WinCrypto(cert)
                }
                #[cfg(not(all(feature = "wincrypto", target_os = "windows")))]
                {
                    DtlsCertInner::WinCrypto(DummyCert(p))
                }
            }
        };

        DtlsCert(inner)
    }

    pub(crate) fn crypto_provider(&self) -> CryptoProvider {
        match self.0 {
            DtlsCertInner::OpenSsl(_) => CryptoProvider::OpenSsl,
            DtlsCertInner::WinCrypto(_) => CryptoProvider::WinCrypto,
        }
    }

    /// Creates a fingerprint for this certificate.
    ///
    /// Fingerprints are used to verify a remote peer's certificate.
    pub fn fingerprint(&self) -> Fingerprint {
        match &self.0 {
            DtlsCertInner::OpenSsl(v) => v.fingerprint(),
            DtlsCertInner::WinCrypto(v) => v.fingerprint(),
            _ => unreachable!(),
        }
    }

    pub(crate) fn create_dtls_impl(&self) -> Result<DtlsImpl, CryptoError> {
        let imp = match &self.0 {
            DtlsCertInner::OpenSsl(v) => DtlsImpl::OpenSsl(v.new_dtls_impl()?),
            DtlsCertInner::WinCrypto(v) => DtlsImpl::WinCrypto(v.new_dtls_impl()?),
        };

        Ok(imp)
    }
}

impl fmt::Debug for DtlsCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            DtlsCertInner::OpenSsl(c) => c.fmt(f),
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

pub(crate) enum DtlsImpl {
    #[cfg(feature = "openssl")]
    OpenSsl(super::ossl::OsslDtlsImpl),
    #[cfg(not(feature = "openssl"))]
    OpenSsl(DummyDtlsImpl),
    #[cfg(all(feature = "wincrypto", target_os = "windows"))]
    WinCrypto(super::wincrypto::WinCryptoDtls),
    #[cfg(not(all(feature = "wincrypto", target_os = "windows")))]
    WinCrypto(DummyDtlsImpl),
}

impl DtlsImpl {
    pub fn set_active(&mut self, active: bool) {
        match self {
            DtlsImpl::OpenSsl(v) => v.set_active(active),
            DtlsImpl::WinCrypto(v) => v.set_active(active),
        }
    }

    pub fn handle_handshake(&mut self, o: &mut VecDeque<DtlsEvent>) -> Result<bool, CryptoError> {
        match self {
            DtlsImpl::OpenSsl(i) => i.handle_handshake(o),
            DtlsImpl::WinCrypto(i) => i.handle_handshake(o),
        }
    }

    pub fn is_active(&self) -> Option<bool> {
        match self {
            DtlsImpl::OpenSsl(i) => i.is_active(),
            DtlsImpl::WinCrypto(i) => i.is_active(),
        }
    }

    pub fn handle_receive(
        &mut self,
        m: &[u8],
        o: &mut VecDeque<DtlsEvent>,
    ) -> Result<(), CryptoError> {
        match self {
            DtlsImpl::OpenSsl(i) => i.handle_receive(m, o),
            DtlsImpl::WinCrypto(i) => i.handle_receive(m, o),
        }
    }

    pub fn poll_datagram(&mut self) -> Option<DatagramSend> {
        match self {
            DtlsImpl::OpenSsl(i) => i.poll_datagram(),
            DtlsImpl::WinCrypto(i) => i.poll_datagram(),
        }
    }

    pub fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        match self {
            DtlsImpl::OpenSsl(i) => i.poll_timeout(now),
            DtlsImpl::WinCrypto(i) => i.poll_timeout(now),
        }
    }

    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            DtlsImpl::OpenSsl(i) => i.handle_input(data),
            DtlsImpl::WinCrypto(i) => i.handle_input(data),
        }
    }

    pub fn is_connected(&self) -> bool {
        match self {
            DtlsImpl::OpenSsl(i) => i.is_connected(),
            DtlsImpl::WinCrypto(i) => i.is_connected(),
        }
    }
}

#[derive(Debug, Clone)]
struct DummyCert(CryptoProvider);

impl DummyCert {
    fn fingerprint(&self) -> Fingerprint {
        panic!("Must enable feature: {}", self.0)
    }

    fn new_dtls_impl(&self) -> Result<DummyDtlsImpl, CryptoError> {
        panic!("Must enable feature: {}", self.0)
    }
}

pub struct DummyDtlsImpl(CryptoProvider);

impl DummyDtlsImpl {
    fn set_active(&self, active: bool) {
        panic!("Must enable feature: {}", self.0)
    }

    fn handle_handshake(&self, o: &mut VecDeque<DtlsEvent>) -> Result<bool, CryptoError> {
        panic!("Must enable feature: {}", self.0)
    }

    fn is_active(&self) -> Option<bool> {
        panic!("Must enable feature: {}", self.0)
    }

    fn handle_receive(&self, m: &[u8], o: &mut VecDeque<DtlsEvent>) -> Result<(), CryptoError> {
        panic!("Must enable feature: {}", self.0)
    }

    fn poll_datagram(&self) -> Option<DatagramSend> {
        panic!("Must enable feature: {}", self.0)
    }

    fn poll_timeout(&self, now: Instant) -> Option<Instant> {
        panic!("Must enable feature: {}", self.0)
    }

    fn handle_input(&self, data: &[u8]) -> Result<(), CryptoError> {
        panic!("Must enable feature: {}", self.0)
    }

    fn is_connected(&self) -> bool {
        panic!("Must enable feature: {}", self.0)
    }
}
