#![allow(clippy::manual_range_contains)]
#![allow(clippy::new_without_default)]

use std::convert::TryFrom;
use std::fmt;
use std::io;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

// Re-export types from str0m-ice
pub use str0m_ice::{NetError, Protocol, StunMessage, StunPacket, TcpType};

// We need our own Receive type that wraps our DatagramRecv
#[derive(Debug, Serialize, Deserialize)]
/// Received incoming data.
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
}

pub(crate) use str0m_ice::stun::Id;

pub use str0m_proto::DATAGRAM_MTU;
pub use str0m_proto::DATAGRAM_MTU_WARN;

/// Max UDP packet size
#[allow(dead_code)]
pub(crate) const DATAGRAM_MAX_PACKET_SIZE: usize = 2000;

/// Max expected RTP header over, with full extensions etc.
#[allow(dead_code)]
pub const MAX_RTP_OVERHEAD: usize = 80;

use std::ops::Deref;

/// An instruction to send an outgoing packet.
#[derive(Serialize, Deserialize)]
pub struct Transmit {
    /// Protocol the transmission should use.
    pub proto: Protocol,
    /// The source IP this packet should be sent from.
    pub source: SocketAddr,
    /// The destination address this datagram should be sent to.
    pub destination: SocketAddr,
    /// Contents of the datagram.
    pub contents: DatagramSend,
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

impl Deref for DatagramSend {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
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
        })
    }
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
        })
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
}
