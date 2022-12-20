//! Low-level protocol logic for the SCTP protocol
//!
//! sctp-proto contains a fully deterministic implementation of SCTP protocol logic. It contains
//! no networking code and does not get any relevant timestamps from the operating system. Most
//! users may want to use the futures-based sctp-async API instead.
//!
//! The sctp-proto API might be of interest if you want to use it from a C or C++ project
//! through C bindings or if you want to use a different event loop than the one tokio provides.
//!
//! The most important types are `Endpoint`, which conceptually represents the protocol state for
//! a single socket and mostly manages configuration and dispatches incoming datagrams to the
//! related `Association`. `Association` types contain the bulk of the protocol logic related to
//! managing a single association and all the related state (such as streams).

#![allow(clippy::too_many_arguments)]

#[macro_use]
extern crate tracing;

use bytes::Bytes;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    ops,
};

mod association;
pub use crate::association::{
    stats::AssociationStats,
    stream::{ReliabilityType, Stream, StreamEvent, StreamId, StreamState},
    Association, AssociationError, Event,
};

pub(crate) mod chunk;
pub use crate::chunk::{
    chunk_payload_data::{ChunkPayloadData, PayloadProtocolIdentifier},
    ErrorCauseCode,
};

mod config;
pub use crate::config::{ClientConfig, EndpointConfig, ServerConfig, TransportConfig};

mod endpoint;
pub use crate::endpoint::{AssociationHandle, ConnectError, DatagramEvent, Endpoint};

mod error;
pub use crate::error::Error as SctpError;

mod packet;

mod shared;
pub use crate::shared::{AssociationEvent, AssociationId, EcnCodepoint, EndpointEvent};

pub(crate) mod param;

pub(crate) mod queue;
pub use crate::queue::reassembly_queue::{Chunk, Chunks};

pub(crate) mod util;

mod dcep;
pub use dcep::{DcepAck, DcepOpen};

/// Whether an endpoint was the initiator of an association
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Side {
    /// The initiator of an association
    Client = 0,
    /// The acceptor of an association
    Server = 1,
}

impl Default for Side {
    fn default() -> Self {
        Side::Client
    }
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            Side::Client => "Client",
            Side::Server => "Server",
        };
        write!(f, "{}", s)
    }
}

impl Side {
    #[inline]
    /// Shorthand for `self == Side::Client`
    pub fn is_client(self) -> bool {
        self == Side::Client
    }

    #[inline]
    /// Shorthand for `self == Side::Server`
    pub fn is_server(self) -> bool {
        self == Side::Server
    }
}

impl ops::Not for Side {
    type Output = Side;
    fn not(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }
}

use crate::packet::PartialDecode;

/// Payload in Incoming/outgoing Transmit
#[derive(Debug)]
pub enum Payload {
    PartialDecode(PartialDecode),
    RawEncode(Vec<Bytes>),
}

/// Incoming/outgoing Transmit
#[derive(Debug)]
pub struct Transmit {
    /// Received/Sent time
    pub now: Instant,
    /// The socket this datagram should be sent to
    pub remote: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Optional local IP address for the datagram
    pub local_ip: Option<IpAddr>,
    /// Payload of the datagram
    pub payload: Payload,
}

/// Helper to bridge `Endpoint` and `Association` into str0m `Rtc`.
pub struct RtcAssociation {
    endpoint: Endpoint,
    association: (AssociationHandle, Association),
    transmit: Option<Transmit>,
    recs: Vec<StreamRec>,
    pushed_back_transmit: Option<Vec<u8>>,
}

#[derive(Default)]
struct StreamRec {
    id: u16,
    open: bool,
    event_open: bool,
    event_close: bool,
    dcep: Option<DcepOpen>,
}

pub enum SctpInput<'a> {
    Data(&'a mut [u8]),
}

pub enum SctpEvent {
    Open(u16, DcepOpen),
    Close(u16),
    Data(u16, SctpData),
    Transmit(Vec<u8>),
}

/// Holder of binary or text data.
#[derive(PartialEq, Eq)]
pub enum SctpData {
    String(String),
    Binary(Vec<u8>),
}

impl SctpData {
    pub fn len(&self) -> usize {
        match self {
            SctpData::String(v) => v.as_bytes().len(),
            SctpData::Binary(v) => v.len(),
        }
    }
}

impl RtcAssociation {
    pub fn new() -> Self {
        let config = EndpointConfig::default();
        let server_config = ServerConfig::default();
        let mut endpoint = Endpoint::new(Arc::new(config), Some(Arc::new(server_config)));
        let config = ClientConfig::default();
        let association = endpoint
            .connect(config, "1.1.1.1:5000".parse().unwrap())
            .expect("to create association");
        RtcAssociation {
            endpoint,
            association,
            transmit: None,
            recs: vec![],
            pushed_back_transmit: None,
        }
    }

    pub fn handle_input(&mut self, input: SctpInput<'_>, now: Instant) -> Result<(), SctpError> {
        match input {
            SctpInput::Data(data) => {
                let remote = "127.0.0.1:5000".parse().unwrap();
                // TODO, remove Bytes in sctp and just use &[u8].
                let data = data.to_vec().into();
                let r = self.endpoint.handle(now, remote, None, None, data);
                if let Some((handle, event)) = r {
                    match event {
                        DatagramEvent::AssociationEvent(event) => {
                            self.association.1.handle_event(event);
                        }
                        DatagramEvent::NewAssociation(a) => {
                            self.association = (handle, a);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn open_stream(&mut self, id: u16, dcep: &DcepOpen) -> Result<(), SctpError> {
        let mut stream = self
            .association
            .1
            .open_stream(id, PayloadProtocolIdentifier::Unknown)?;

        stream.set_reliability_params(
            dcep.unordered,
            dcep.channel_type,
            dcep.reliability_parameter,
        )?;

        let rec = stream_rec(&mut self.recs, id);

        rec.dcep = Some(dcep.clone());

        Ok(())
    }

    pub fn is_open(&mut self, id: u16) -> bool {
        let rec = stream_rec(&mut self.recs, id);
        rec.open && rec.event_open
    }

    pub fn write(&mut self, id: u16, binary: bool, buf: &[u8]) -> Result<usize, SctpError> {
        let mut stream = self.association.1.stream(id)?;

        let ppi = if buf.is_empty() {
            if binary {
                PayloadProtocolIdentifier::BinaryEmpty
            } else {
                PayloadProtocolIdentifier::StringEmpty
            }
        } else {
            if binary {
                PayloadProtocolIdentifier::Binary
            } else {
                PayloadProtocolIdentifier::String
            }
        };

        // RFC 8831
        // SCTP does not support the sending of empty user messages. Therefore, if an empty message
        // has to be sent, the appropriate PPID (WebRTC String Empty or WebRTC Binary Empty) is used,
        // and the SCTP user message of one zero byte is sent.
        let buf = if buf.is_empty() { &[0] } else { buf };

        let n = stream.write(&buf, ppi)?;

        let n = if buf.is_empty() { 0 } else { n };

        Ok(n)
    }

    pub fn push_back_transmit(&mut self, buf: Vec<u8>) {
        assert!(self.pushed_back_transmit.is_none());
        self.pushed_back_transmit = Some(buf);
    }

    pub fn poll_event(&mut self, now: Instant) -> Option<SctpEvent> {
        if let Some(buf) = self.pushed_back_transmit.take() {
            return Some(SctpEvent::Transmit(buf));
        }

        while let Some(t) = self.poll_transmit(now) {
            if let Payload::RawEncode(v) = t.payload {
                let len = v.iter().map(|b| b.len()).sum();
                let mut buf = vec![0; len];
                let mut n = 0;
                for b in v {
                    let l = b.len();
                    (&mut buf[n..(n + l)]).copy_from_slice(&b);
                    n += l;
                }
                return Some(SctpEvent::Transmit(buf));
            } else {
                continue;
            }
        }

        // propagate events between endpoint and association.
        while let Some(e) = self.association.1.poll_endpoint_event() {
            if let Some(ae) = self.endpoint.handle_event(self.association.0, e) {
                self.association.1.handle_event(ae);
            }
        }

        while let Some(e) = self.association.1.poll() {
            if let Event::Stream(e) = e {
                let streams = &mut self.recs;

                match e {
                    StreamEvent::Readable { id } | StreamEvent::Writable { id } => {
                        // This simply instantiates a StreamRec so we now to poll read below.
                        stream_rec(streams, id);
                    }
                    StreamEvent::Finished { id } => {
                        let rec = stream_rec(streams, id);
                        rec.open = false
                    }
                    StreamEvent::Stopped { id, .. } => {
                        let rec = stream_rec(streams, id);
                        rec.open = false
                    }
                    _ => {}
                }
            }
        }

        // Remove unused streams.
        // Keep open streams and streams that have been communicated as open (event_open),
        // but not yet been communicated as closed (event_closed).
        self.recs
            .retain(|s| s.open || (s.event_open && !s.event_close));

        for rec in &mut self.recs {
            if !rec.open {
                if !rec.event_close {
                    rec.event_close = true;
                    return Some(SctpEvent::Close(rec.id));
                } else {
                    continue;
                }
            }

            if let Ok(stream) = self.association.1.stream(rec.id) {
                match read_from_stream(stream, rec) {
                    Ok(Some(v)) => {
                        return Some(v);
                    }
                    Err(_e) => {
                        rec.open = false;
                        rec.event_close = true;
                        return Some(SctpEvent::Close(rec.id));
                    }
                    _ => {}
                }
            } else {
                rec.open = false;
                rec.event_close = true;
                return Some(SctpEvent::Close(rec.id));
            }
        }

        None
    }

    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit> {
        if let Some(t) = self.transmit.take() {
            return Some(t);
        }

        if let Some(t) = self.endpoint.poll_transmit() {
            return Some(t);
        }

        if let Some(t) = self.association.1.poll_transmit(now) {
            return Some(t);
        }

        None
    }
}

fn stream_rec(streams: &mut Vec<StreamRec>, id: u16) -> &mut StreamRec {
    let idx = streams.iter().position(|r| r.id == id);

    if let Some(idx) = idx {
        return &mut streams[idx];
    } else {
        let r = StreamRec {
            id,
            open: true,
            ..Default::default()
        };
        streams.push(r);
        streams.last_mut().unwrap()
    }
}

fn read_from_stream(
    mut stream: Stream<'_>,
    rec: &mut StreamRec,
) -> Result<Option<SctpEvent>, SctpError> {
    if !stream.is_readable() {
        return Ok(None);
    }
    let res = stream.read()?;

    let Some(c) = res else {
        return Ok(None);
    };

    let mut buf = vec![0; c.len()];
    let n = c.read(&mut buf[..])?;
    assert!(n == buf.len());

    if !rec.event_open {
        rec.event_open = true;

        let dcep = if let Some(dcep) = rec.dcep.take() {
            // Channel is open locally and we send the initial DCEP

            let mut buf = vec![0; 1500];
            let n = dcep.marshal_to(&mut buf);
            buf.truncate(n);

            stream.write(&buf, PayloadProtocolIdentifier::Dcep)?;

            dcep
        } else {
            // Remote side opened channel, and we are responding to the initial DCEP

            let dcep: DcepOpen = buf.as_slice().try_into()?;

            stream.set_reliability_params(
                dcep.unordered,
                dcep.channel_type,
                dcep.reliability_parameter,
            )?;

            let mut buf = [0];
            DcepAck.marshal_to(&mut buf);
            stream.write(&buf, PayloadProtocolIdentifier::Dcep)?;

            dcep
        };

        return Ok(Some(SctpEvent::Open(rec.id, dcep)));
    }

    let data = match c.ppi {
        PayloadProtocolIdentifier::String => {
            let s = String::from_utf8(buf).map_err(|_| SctpError::Other("Bad UTF-8".into()))?;
            SctpData::String(s)
        }
        PayloadProtocolIdentifier::Binary => SctpData::Binary(buf),
        PayloadProtocolIdentifier::StringEmpty => SctpData::String(String::new()),
        PayloadProtocolIdentifier::BinaryEmpty => SctpData::Binary(Vec::new()),
        _ => {
            return Err(SctpError::Other("Unexpected PPI".into()));
        }
    };

    Ok(Some(SctpEvent::Data(rec.id, data)))
}

impl fmt::Debug for SctpData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(v) => f.debug_tuple("String").field(&truncate(v, 10)).finish(),
            Self::Binary(v) => f.debug_tuple("Binary").field(&v.len()).finish(),
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    let has_more = s.chars().take(n + 1).count() > n;
    let mut r: String = s.chars().take(n).collect();
    if has_more {
        r.push('…');
    }
    r
}

impl Deref for SctpData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            SctpData::String(v) => v.as_bytes(),
            SctpData::Binary(v) => v.as_slice(),
        }
    }
}
