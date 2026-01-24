#![allow(clippy::manual_range_contains)]
#![allow(clippy::new_without_default)]

use std::convert::TryFrom;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Instant;

use serde::{Deserialize, Serialize};

mod stun;
pub(crate) use stun::{Class as StunClass, DEFAULT_MAX_RETRANSMITS};
pub(crate) use stun::{Method as StunMethod, StunTiming};
pub use stun::{StunMessage, StunMessageBuilder, TransId};

mod id;
// this is only exported from this crate to avoid needing
// a "util" crate or similar.
pub(crate) use id::Id;

pub use str0m_proto::DATAGRAM_MTU;
pub use str0m_proto::DATAGRAM_MTU_WARN;

/// Max UDP packet size
pub(crate) const DATAGRAM_MAX_PACKET_SIZE: usize = 2000;

/// Max expected RTP header over, with full extensions etc.
pub const MAX_RTP_OVERHEAD: usize = 80;

mod error;
pub use self::error::{NetError, StunError};

/// Type of protocol used in [`Transmit`] and [`Receive`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    /// UDP
    Udp,
    /// TCP (See RFC 4571 for framing)
    Tcp,
    /// TCP with fixed SSL Hello Exchange
    /// See AsyncSSLServerSocket implementation for exchange details:
    /// <https://webrtc.googlesource.com/src/+/refs/heads/main/rtc_base/server_socket_adapters.cc#19>
    SslTcp,
    /// TLS (only used via relay)
    Tls,
}

/// TCP connection role as defined by the `tcptype` SDP attribute.
///
/// This enum corresponds to the TCP connection setup modes defined in
/// [RFC 6544 §4.5](https://datatracker.ietf.org/doc/html/rfc6544#section-4.5),
/// which specifies how endpoints establish TCP connections when TCP is used
/// as a transport for media streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpType {
    /// The endpoint actively initiates the TCP connection.
    ///
    /// In this mode, the endpoint performs an active open (i.e., sends a SYN)
    /// to the remote peer.
    Active,

    /// The endpoint passively waits for an incoming TCP connection.
    ///
    /// In this mode, the endpoint performs a passive open (i.e., listens)
    /// and accepts a connection initiated by the remote peer.
    Passive,

    /// Simultaneous open.
    ///
    /// Both endpoints attempt to actively open a TCP connection to each other
    /// at the same time. This relies on TCP simultaneous open behavior.
    So,
}

impl fmt::Display for TcpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::So => "so",
        };
        f.write_str(str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTcpTypeError;

impl fmt::Display for ParseTcpTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid TCP type (expected: active, passive, or so)")
    }
}

impl std::error::Error for ParseTcpTypeError {}

impl FromStr for TcpType {
    type Err = ParseTcpTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s.eq_ignore_ascii_case("active") => Ok(Self::Active),
            _ if s.eq_ignore_ascii_case("passive") => Ok(Self::Passive),
            _ if s.eq_ignore_ascii_case("so") => Ok(Self::So),
            _ => Err(ParseTcpTypeError),
        }
    }
}

/// An instruction to send an outgoing packet.
#[derive(Serialize, Deserialize)]
pub struct Transmit {
    /// Protocol the transmission should use.
    ///
    /// Provided to each of the [`Candidate`][crate::Candidate] constructors.
    pub proto: Protocol,

    /// The source IP this packet should be sent from.
    ///
    /// For ICE it's important to send outgoing packets from the correct IP address.
    /// The IP could come from a local socket or relayed over a TURN server. Features like
    /// hole-punching will only work if the packets are routed through the correct interfaces.
    ///
    /// This address will either be:
    /// - The address of a socket you have bound locally, such as
    ///   with [`UdpSocket::bind`][std::net::UdpSocket].
    /// - The address of a relay socket that you have
    ///   [allocated](https://www.rfc-editor.org/rfc/rfc8656#name-allocations-2) using TURN.
    ///
    /// To correctly handle an instance of [`Transmit`], you should:
    ///
    /// - Check if [`Transmit::source`] corresponds to one of your local sockets,
    ///   if yes, send it through that.
    /// - Check if [`Transmit::source`] corresponds to one of your relay sockets (i.e. allocations),
    ///   if yes, send it via one of:
    ///     - a [TURN channel data message](https://www.rfc-editor.org/rfc/rfc8656#name-sending-a-channeldata-messa)
    ///     - a [SEND indication](https://www.rfc-editor.org/rfc/rfc8656#name-send-and-data-methods)
    ///
    /// `str0m` learns about the source address using [`Candidate`][crate::Candidate] that are added using
    /// [`Rtc::add_local_candidate`][crate::Rtc::add_local_candidate].
    ///
    /// The different candidate types are:
    ///
    /// * [`Candidate::host()`][crate::Candidate::host]: Used for locally bound UDP sockets.
    /// * [`Candidate::relayed()`][crate::Candidate::relayed]: Used for sockets relayed via some
    ///     other server (normally TURN).
    /// * [`Candidate::server_reflexive()`][crate::Candidate::server_reflexive]: Used when a local
    ///     (host) socket appears as some another IP address to the remote peer (usually due to a
    ///     NAT firewall on the local side). STUN servers can be used to discover the external address.
    ///     In this case the `base` parameter to `server_reflexive()` is the local address and
    ///     used for [`Transmit::source`].
    /// * `Peer reflexive` is another, internal, type of candidate that str0m infers by using the other
    ///     types of candidates.
    pub source: SocketAddr,

    /// The destination address this datagram should be sent to.
    ///
    /// This will be one of the [`Candidate`][crate::Candidate] provided explicitly using
    /// [`Rtc::add_remote_candidate`][crate::Rtc::add_remote_candidate] or via SDP negotiation.
    pub destination: SocketAddr,

    /// Contents of the datagram.
    pub contents: DatagramSend,
}

/// A wrapper for some payload that is to be sent.
#[derive(Debug, Serialize, Deserialize)]
pub struct DatagramSend(Vec<u8>);

impl From<Vec<u8>> for DatagramSend {
    fn from(value: Vec<u8>) -> Self {
        DatagramSend(value)
    }
}

impl From<DatagramSend> for Vec<u8> {
    fn from(value: DatagramSend) -> Self {
        value.0
    }
}

/// Received incoming data.
#[derive(Debug, Serialize, Deserialize)]
pub struct Receive<'a> {
    /// The protocol the socket this received data originated from is using.
    pub proto: Protocol,

    /// The socket this received data originated from.
    pub source: SocketAddr,

    /// The destination ip of the datagram.
    pub destination: SocketAddr,

    /// Parsed contents of the datagram.
    #[serde(borrow)]
    pub contents: DatagramRecv<'a>,

    /// The timestamp when the data was received.
    ///
    /// This is used internally by str0m for timing calculations.
    #[serde(skip)]
    pub timestamp: Option<Instant>,
}

impl<'a> Receive<'a> {
    /// Creates a new instance by trying to parse the contents of `buf`.
    pub fn new(
        proto: Protocol,
        source: SocketAddr,
        destination: SocketAddr,
        buf: &'a [u8],
    ) -> Result<Self, NetError> {
        let contents = DatagramRecv::try_from(buf)?;
        Ok(Receive {
            proto,
            source,
            destination,
            contents,
            timestamp: None,
        })
    }

    /// Creates a new instance with a timestamp.
    pub fn with_timestamp(
        proto: Protocol,
        source: SocketAddr,
        destination: SocketAddr,
        buf: &'a [u8],
        timestamp: Instant,
    ) -> Result<Self, NetError> {
        let contents = DatagramRecv::try_from(buf)?;
        Ok(Receive {
            proto,
            source,
            destination,
            contents,
            timestamp: Some(timestamp),
        })
    }

    /// Sets the timestamp on this receive.
    pub fn set_timestamp(&mut self, timestamp: Instant) {
        self.timestamp = Some(timestamp);
    }

    /// Gets the timestamp, if set.
    pub fn timestamp(&self) -> Option<Instant> {
        self.timestamp
    }
}

/// An incoming STUN packet.
#[derive(Debug)]
pub struct StunPacket<'a> {
    /// The protocol the socket this received data originated from is using.
    pub proto: Protocol,
    /// The socket this received data originated from.
    pub source: SocketAddr,
    /// The destination socket of the datagram.
    pub destination: SocketAddr,
    /// The STUN message.
    pub message: StunMessage<'a>,
}

/// Wrapper for a parsed payload to be received.
#[derive(Serialize, Deserialize)]
pub struct DatagramRecv<'a> {
    #[serde(borrow)]
    pub(crate) inner: DatagramRecvInner<'a>,
}

#[allow(clippy::large_enum_variant)] // We purposely don't want to allocate.
#[derive(Serialize, Deserialize)]
pub(crate) enum DatagramRecvInner<'a> {
    Stun(StunMessage<'a>),
    Dtls(&'a [u8]),
    Rtp(&'a [u8]),
    Rtcp(&'a [u8]),
}

impl<'a> TryFrom<&'a [u8]> for DatagramRecv<'a> {
    type Error = NetError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        use DatagramRecvInner::*;

        let kind = MultiplexKind::try_from(value)?;

        let inner = match kind {
            MultiplexKind::Stun => Stun(StunMessage::parse(value)?),
            MultiplexKind::Dtls => Dtls(value),
            MultiplexKind::Rtp => Rtp(value),
            MultiplexKind::Rtcp => Rtcp(value),
        };

        Ok(DatagramRecv { inner })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum MultiplexKind {
    Stun,
    Dtls,
    Rtp,
    Rtcp,
}

impl<'a> TryFrom<&'a [u8]> for MultiplexKind {
    type Error = io::Error;

    fn try_from(value: &'a [u8]) -> Result<Self, io::Error> {
        if value.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty datagram"));
        }

        let byte0 = value[0];
        let len = value.len();

        if byte0 < 2 && len >= 20 {
            Ok(MultiplexKind::Stun)
        } else if byte0 >= 20 && byte0 < 64 {
            Ok(MultiplexKind::Dtls)
        } else if byte0 >= 128 && byte0 < 192 && len > 2 {
            let byte1 = value[1];
            let payload_type = byte1 & 0x7f;

            Ok(if payload_type < 64 {
                // This is kinda novel, and probably breaks, but...
                // we can use the < 64 pt as an escape hatch if we run out
                // of dynamic numbers >= 96
                // https://bugs.chromium.org/p/webrtc/issues/detail?id=12194
                MultiplexKind::Rtp
            } else if payload_type >= 64 && payload_type < 96 {
                MultiplexKind::Rtcp
            } else {
                MultiplexKind::Rtp
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown datagram",
            ))
        }
    }
}

impl<'a> TryFrom<&'a Transmit> for Receive<'a> {
    type Error = NetError;

    fn try_from(t: &'a Transmit) -> Result<Self, Self::Error> {
        Ok(Receive {
            proto: t.proto,
            source: t.source,
            destination: t.destination,
            contents: DatagramRecv::try_from(&t.contents[..])?,
            timestamp: None,
        })
    }
}

impl fmt::Debug for Transmit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transmit")
            .field("proto", &self.proto)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("len", &self.contents.len())
            .finish()
    }
}

impl Deref for DatagramSend {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for DatagramRecv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl fmt::Debug for DatagramRecvInner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stun(v) => f.debug_tuple("Stun").field(v).finish(),
            Self::Dtls(v) => write!(f, "Dtls(len: {})", v.len()),
            Self::Rtp(v) => write!(f, "Rtp(len: {})", v.len()),
            Self::Rtcp(v) => write!(f, "Rtcp(len: {})", v.len()),
        }
    }
    //
}

impl TryFrom<&str> for Protocol {
    type Error = ();

    fn try_from(proto: &str) -> Result<Self, Self::Error> {
        let proto = proto.to_lowercase();
        match proto.as_str() {
            "udp" => Ok(Protocol::Udp),
            "tcp" => Ok(Protocol::Tcp),
            "ssltcp" => Ok(Protocol::SslTcp),
            "tls" => Ok(Protocol::Tls),
            _ => Err(()),
        }
    }
}

impl From<Protocol> for &str {
    fn from(proto: Protocol) -> Self {
        match proto {
            Protocol::Udp => "udp",
            Protocol::Tcp => "tcp",
            Protocol::SslTcp => "ssltcp",
            Protocol::Tls => "tls",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let x: &str = (*self).into();
        write!(f, "{}", x)
    }
}
