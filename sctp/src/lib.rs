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

#![warn(rust_2018_idioms)]
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

#[macro_use]
extern crate tracing;

use bytes::Bytes;
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

pub struct RtcAssociation {
    endpoint: Endpoint,
    association: Option<(AssociationHandle, Association)>,
    transmit: Option<Transmit>,
    recs: Vec<StreamRec>,
}

struct StreamRec {
    id: u16,
    open: bool,
}

impl RtcAssociation {
    pub fn new() -> Self {
        let config = EndpointConfig::default();
        let server_config = ServerConfig::default();
        let endpoint = Endpoint::new(Arc::new(config), Some(Arc::new(server_config)));
        RtcAssociation {
            endpoint,
            association: None,
            transmit: None,
            recs: vec![],
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
                            if let Some(a) = &mut self.association {
                                a.1.handle_event(event);
                            }
                        }
                        DatagramEvent::NewAssociation(a) => {
                            self.association = Some((handle, a));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn poll_event(&mut self, now: Instant) -> Option<SctpEvent> {
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
                return Some(SctpEvent::Output(buf));
            } else {
                continue;
            }
        }

        if let Some(a) = &mut self.association {
            // propagate events between endpoint and association.
            while let Some(e) = a.1.poll_endpoint_event() {
                if let Some(ae) = self.endpoint.handle_event(a.0, e) {
                    a.1.handle_event(ae);
                }
            }

            while let Some(e) = a.1.poll() {
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

            // remove unused streams
            self.recs.retain(|s| s.open);

            for rec in &mut self.recs {
                if let Ok(mut stream) = a.1.stream(rec.id) {
                    if stream.is_readable() {
                        if let Ok(res) = stream.read() {
                            if let Some(c) = res {
                                let mut buf = vec![0; c.len()];
                                if let Ok(n) = c.read(&mut buf[..]) {
                                    assert!(n == buf.len());
                                    return Some(SctpEvent::Data(buf));
                                } else {
                                    rec.open = false;
                                }
                            }
                        } else {
                            rec.open = false;
                        }
                    }
                } else {
                    rec.open = false;
                }
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

        if let Some(a) = &mut self.association {
            if let Some(t) = a.1.poll_transmit(now) {
                return Some(t);
            }
        }

        None
    }
}

pub enum SctpInput<'a> {
    Data(&'a mut [u8]),
}

pub enum SctpEvent {
    Data(Vec<u8>),
    Output(Vec<u8>),
}

fn stream_rec(streams: &mut Vec<StreamRec>, id: u16) -> &mut StreamRec {
    let idx = streams.iter().position(|r| r.id == id);

    if let Some(idx) = idx {
        return &mut streams[idx];
    } else {
        let r = StreamRec { id, open: true };
        streams.push(r);
        streams.last_mut().unwrap()
    }
}
