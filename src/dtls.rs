use std::collections::VecDeque;
use std::time::Instant;
use std::{fmt, io};
use thiserror::Error;

use crate::crypto::{CryptoError, DtlsImpl, Fingerprint};

pub use crate::crypto::{DtlsCert, DtlsCertOptions, DtlsEvent};
use crate::net::DatagramSend;

/// Errors that can arise in DTLS.
#[derive(Debug, Error)]
pub enum DtlsError {
    /// Error arising in the crypto
    #[error("{0}")]
    CryptoError(CryptoError),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),
}

impl DtlsError {
    pub(crate) fn is_would_block(&self) -> bool {
        #[allow(irrefutable_let_patterns)]
        let DtlsError::Io(e) = self
        else {
            return false;
        };
        e.kind() == io::ErrorKind::WouldBlock
    }
}

/// Encapsulation of DTLS.
pub struct Dtls {
    dtls_impl: DtlsImpl,

    /// The fingerprint of the certificate.
    fingerprint: Fingerprint,

    /// Remote fingerprint.
    remote_fingerprint: Option<Fingerprint>,

    /// Events ready to be polled.
    events: VecDeque<DtlsEvent>,
}

impl Dtls {
    /// Creates a new instance.
    ///
    /// `active` indicates whether this side should initiate the handshake or not.
    /// This in turn is governed by the `a=setup` SDP attribute.
    pub fn new(cert: DtlsCert) -> Result<Self, DtlsError> {
        let dtls_impl = cert.create_dtls_impl()?;
        let fingerprint = cert.fingerprint();

        Ok(Self {
            dtls_impl,
            fingerprint,
            remote_fingerprint: None,
            events: VecDeque::new(),
        })
    }

    /// Tells if this instance has been inited.
    ///
    /// Once true, we cannot do `set_active` anymore.
    pub fn is_inited(&self) -> bool {
        self.is_active().is_some()
    }

    /// Set whether this instance is active or passive.
    ///
    /// i.e. initiating the client hello or not. This must be called
    /// exactly once before starting to handshake (I/O).
    pub fn set_active(&mut self, active: bool) {
        self.dtls_impl.set_active(active)
    }

    /// If set_active, returns what was set.
    pub fn is_active(&self) -> Option<bool> {
        self.dtls_impl.is_active()
    }

    /// The local fingerprint.
    ///
    /// To be communicated in SDP offers sent to the remote peer.
    pub fn local_fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Remote fingerprint.
    pub fn remote_fingerprint(&self) -> &Option<Fingerprint> {
        &self.remote_fingerprint
    }

    /// Poll for the next datagram to send.
    pub fn poll_datagram(&mut self) -> Option<DatagramSend> {
        self.dtls_impl.poll_datagram()
    }

    /// Poll for a timeout.
    pub fn poll_timeout(&mut self, now: Instant) -> Option<Instant> {
        self.dtls_impl.poll_timeout(now)
    }

    /// Poll for an event.
    pub fn poll_event(&mut self) -> Option<DtlsEvent> {
        let x = self.events.pop_front();
        if x.is_some() {
            trace!("Poll event: {:?}", x);
        }
        x
    }

    /// Handling incoming data to be sent as DTLS datagrams.
    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), DtlsError> {
        Ok(self.dtls_impl.handle_input(data)?)
    }

    /// Handles an incoming DTLS datagrams.
    pub fn handle_receive(&mut self, message: &[u8]) -> Result<(), DtlsError> {
        if self.dtls_impl.is_active().is_none() {
            debug!("Ignoring DTLS datagram prior to DTLS start");
            return Ok(());
        }

        Ok(self.dtls_impl.handle_receive(message, &mut self.events)?)
    }

    /// Handle handshaking.
    ///
    /// Once handshaken, this becomes a noop.
    pub fn handle_handshake(&mut self) -> Result<bool, DtlsError> {
        let len_before = self.events.len();
        let result = self.dtls_impl.handle_handshake(&mut self.events)?;

        if self.remote_fingerprint.is_none() && self.events.len() > len_before {
            for ev in &self.events {
                if let DtlsEvent::RemoteFingerprint(fingerprint) = ev {
                    self.remote_fingerprint = Some(fingerprint.clone());
                }
            }
        }

        Ok(result)
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.dtls_impl.is_connected()
    }
}

impl fmt::Debug for DtlsEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected => write!(f, "Connected"),
            Self::SrtpKeyingMaterial(keying_mat, srtp_profile) => f
                .debug_tuple("SrtpKeyingMaterial")
                .field(keying_mat)
                .field(srtp_profile)
                .finish(),
            Self::RemoteFingerprint(arg0) => {
                f.debug_tuple("RemoteFingerprint").field(arg0).finish()
            }
            Self::Data(arg0) => f.debug_tuple("Data").field(&arg0.len()).finish(),
        }
    }
}

impl From<CryptoError> for DtlsError {
    fn from(value: CryptoError) -> Self {
        match value {
            CryptoError::Io(error) => DtlsError::Io(error),
            x => DtlsError::CryptoError(x),
        }
    }
}
