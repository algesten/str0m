use std::collections::VecDeque;
use std::io::{self, Read};
use std::net::SocketAddr;

use net::{DatagramRecv, DatagramSend, Receive, DATAGRAM_MTU};
use openssl::ssl::SslContext;

use crate::ossl::{dtls_create_ctx, dtls_ssl_create, KeyingMaterial, TlsStream};
use crate::{DtlsError, Fingerprint};

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
#[derive(Debug)]
pub enum DtlsEvent {
    /// When the DTLS has finished handshaking.
    Connected,

    /// Keying material for SRTP encryption master key.
    SrtpKeyingMaterial(KeyingMaterial),

    /// The fingerprint of the remote peer.
    ///
    /// This should be checked against the fingerprint communicated in the SDP.
    RemoteFingerprint(Fingerprint),
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

    /// Set whether this instance is active or passive.
    ///
    /// i.e. initiating the client helo or not. This must be called
    /// exactly once before starting to handshake (I/O).
    pub fn set_active(&mut self, active: bool) {
        self.tls.set_active(active);
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
        trace!("Poll datagram: {:?}", x);
        x
    }

    /// Poll for an event.
    pub fn poll_event(&mut self) -> Option<DtlsEvent> {
        let x = self.events.pop_front();
        trace!("Poll event: {:?}", x);
        x
    }

    /// Handle handshaking.
    ///
    /// Once handshaken, this becomes a noop.
    pub fn handle_handshake(&mut self) -> Result<(), DtlsError> {
        if self.tls.is_handshaken() {
            // Nice. Nothing to do.
        } else {
            if self.tls.complete_handshake_until_block()? {
                self.events.push_back(DtlsEvent::Connected);

                let (keying_material, fingerprint) = self
                    .tls
                    .take_srtp_keying_material()
                    .expect("Exported keying material");

                self.events
                    .push_back(DtlsEvent::RemoteFingerprint(fingerprint));

                self.events
                    .push_back(DtlsEvent::SrtpKeyingMaterial(keying_material));
            }
        }

        Ok(())
    }

    /// Handles an incoming DTLS datagrams.
    pub fn handle_receive(&mut self, r: Receive) -> Result<(), DtlsError> {
        info!("Handle receive: {:?}", r);

        let message = match r.contents {
            DatagramRecv::Dtls(v) => v,
            _ => {
                trace!("Receive rejected, not DTLS");
                return Ok(());
            }
        };

        self.tls.inner_mut().set_incoming(message);

        let mut buf = vec![0; DATAGRAM_MTU];
        let n = self.tls.read(&mut buf)?;
        buf.truncate(n);

        // TODO: Emit buffer for SCTP. Event? Or new poll queue?

        Ok(())
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

        (&mut buf[0..n]).copy_from_slice(&self.incoming);
        self.incoming.truncate(0);

        Ok(n)
    }
}

impl io::Write for IoBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let dsend = DatagramSend::new(buf.to_vec());

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
