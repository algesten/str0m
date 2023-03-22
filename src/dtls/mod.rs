use openssl::error::ErrorStack;
use openssl::ssl::SslContext;
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use thiserror::Error;

use crate::io::{DatagramRecv, DatagramSend, Receive, DATAGRAM_MTU_WARN};

mod ossl;
pub use ossl::KeyingMaterial;
use ossl::{dtls_create_ctx, dtls_ssl_create, TlsStream};

/// Errors that can arise in DTLS.
#[derive(Debug, Error)]
pub enum DtlsError {
    /// Some error from OpenSSL layer (used for DTLS).
    #[error("{0}")]
    OpenSsl(#[from] ErrorStack),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),
}

impl DtlsError {
    pub(crate) fn is_would_block(&self) -> bool {
        let DtlsError::Io(e) = self else {
            return false;
        };
        e.kind() == io::ErrorKind::WouldBlock
    }
}

/// Certificate fingerprint.
///
/// DTLS uses self signed certificates, and the fingerprint is communicated via
/// SDP to let the remote peer verify who is connecting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    /// Hash function used to produce the `bytes`.
    ///
    /// This is normally `sha-256`.
    pub hash_func: String,

    /// Digest of the certificate by the algorithm in `hash_func`.
    pub bytes: Vec<u8>,
}

/// Encapsulation of DTLS.
pub struct Dtls {
    /// Context belongs together with Fingerprint.
    ///
    /// This just needs to be kept alive since it pins the entire openssl context
    /// from which `Ssl` is created.
    _context: SslContext,

    /// The local fingerprint communicated via SDP to remote.
    fingerprint: Fingerprint,

    /// The actual openssl TLS stream.
    tls: TlsStream<IoBuffer>,

    /// Outgoing events, ready to be polled.
    events: VecDeque<DtlsEvent>,
}

/// Events arising from a [`Dtls`] instance.
pub enum DtlsEvent {
    /// When the DTLS has finished handshaking.
    Connected,

    /// Keying material for SRTP encryption master key.
    SrtpKeyingMaterial(KeyingMaterial),

    /// The fingerprint of the remote peer.
    ///
    /// This should be checked against the fingerprint communicated in the SDP.
    RemoteFingerprint(Fingerprint),

    /// Decrypted data from incoming DTLS traffic.
    Data(Vec<u8>),
}

impl Dtls {
    /// Creates a new instance.
    ///
    /// `active` indicates whether this side should initiate the handshake or not.
    /// This in turn is governed by the `a=setup` SDP attribute.
    pub fn new() -> Result<Self, DtlsError> {
        let (_context, fingerprint) = dtls_create_ctx()?;
        let ssl = dtls_ssl_create(&_context)?;
        Ok(Dtls {
            _context,
            fingerprint,
            tls: TlsStream::new(ssl, IoBuffer::default()),
            events: VecDeque::new(),
        })
    }

    /// Tells if this instance has been inited.
    ///
    /// Once true, we cannot do `set_active` anymore.
    pub fn is_inited(&self) -> bool {
        self.tls.is_inited()
    }

    /// Set whether this instance is active or passive.
    ///
    /// i.e. initiating the client helo or not. This must be called
    /// exactly once before starting to handshake (I/O).
    pub fn set_active(&mut self, active: bool) {
        self.tls.set_active(active);
    }

    /// If set_active, returns what was set.
    pub fn is_active(&self) -> Option<bool> {
        self.tls.is_active()
    }

    /// The local fingerprint.
    ///
    /// To be communicated in SDP offers sent to the remote peer.
    pub fn local_fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Poll for the next datagram to send.
    pub fn poll_datagram(&mut self) -> Option<DatagramSend> {
        let x = self.tls.inner_mut().pop_outgoing();
        if let Some(x) = &x {
            if x.len() > DATAGRAM_MTU_WARN {
                warn!("DTLS above MTU {}: {}", DATAGRAM_MTU_WARN, x.len());
            }
            trace!("Poll datagram: {}", x.len());
        }
        x
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
        Ok(self.tls.write_all(data)?)
    }

    /// Handles an incoming DTLS datagrams.
    pub fn handle_receive(&mut self, r: Receive) -> Result<(), DtlsError> {
        let message = match r.contents {
            DatagramRecv::Dtls(v) => v,
            _ => {
                trace!("Receive rejected, not DTLS");
                return Ok(());
            }
        };

        self.tls.inner_mut().set_incoming(message);

        if self.handle_handshake()? {
            // early return as long as we're handshaking
            return Ok(());
        }

        let mut buf = vec![0; 2000];
        let n = match self.tls.read(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        buf.truncate(n);

        self.events.push_back(DtlsEvent::Data(buf));

        Ok(())
    }

    /// Handle handshaking.
    ///
    /// Once handshaken, this becomes a noop.
    pub fn handle_handshake(&mut self) -> Result<bool, DtlsError> {
        if self.tls.is_handshaken() {
            // Nice. Nothing to do.
            Ok(false)
        } else if self.tls.complete_handshake_until_block()? {
            self.events.push_back(DtlsEvent::Connected);

            let (keying_material, fingerprint) = self
                .tls
                .take_srtp_keying_material()
                .expect("Exported keying material");

            self.events
                .push_back(DtlsEvent::RemoteFingerprint(fingerprint));

            self.events
                .push_back(DtlsEvent::SrtpKeyingMaterial(keying_material));
            Ok(false)
        } else {
            Ok(true)
        }
    }
}

#[derive(Default)]
struct IoBuffer {
    pub incoming: Vec<u8>,
    pub outgoing: VecDeque<DatagramSend>,
}

impl IoBuffer {
    fn set_incoming(&mut self, buf: &[u8]) {
        assert!(self.incoming.is_empty());
        self.incoming.resize(buf.len(), 0);
        self.incoming.copy_from_slice(buf);
    }

    fn pop_outgoing(&mut self) -> Option<DatagramSend> {
        self.outgoing.pop_front()
    }
}

impl io::Read for IoBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.incoming.len();

        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock"));
        }

        // read buffer must read entire packet in one go.
        // we can't fragment incoming datagrams.
        assert!(buf.len() >= n);

        buf[0..n].copy_from_slice(&self.incoming);
        self.incoming.truncate(0);

        Ok(n)
    }
}

impl io::Write for IoBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let dsend = buf.to_vec().into();

        self.outgoing.push_back(dsend);

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DtlsSendAddress {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl fmt::Debug for DtlsEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected => write!(f, "Connected"),
            Self::SrtpKeyingMaterial(arg0) => {
                f.debug_tuple("SrtpKeyingMaterial").field(arg0).finish()
            }
            Self::RemoteFingerprint(arg0) => {
                f.debug_tuple("RemoteFingerprint").field(arg0).finish()
            }
            Self::Data(arg0) => f.debug_tuple("Data").field(&arg0.len()).finish(),
        }
    }
}
