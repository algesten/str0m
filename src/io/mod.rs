#![allow(clippy::manual_range_contains)]
#![allow(clippy::new_without_default)]

use std::convert::TryFrom;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::ops::Deref;

use thiserror::Error;

mod stun;
pub(crate) use stun::stun_resend_delay;
pub(crate) use stun::{
    StunError, StunMessage, TransId, STUN_MAX_RETRANS, STUN_MAX_RTO_MILLIS, STUN_TIMEOUT,
};

mod sha1;
pub(crate) use self::sha1::Sha1;

mod id;
// this is only exported from this crate to avoid needing
// a "util" crate or similar.
pub(crate) use id::Id;

/// Targeted MTU
pub(crate) const DATAGRAM_MTU: usize = 1150;

/// Warn if any packet we are about to send is above this size.
pub(crate) const DATAGRAM_MTU_WARN: usize = 1280;

/// Max UDP packet size
pub(crate) const DATAGRAM_MAX_PACKET_SIZE: usize = 2000;

/// Max expected RTP header over, with full extensions etc.
pub const MAX_RTP_OVERHEAD: usize = 80;

/// Errors from parsing network data.
#[derive(Debug, Error)]
pub enum NetError {
    /// Some STUN protocol error.
    #[error("{0}")]
    Stun(#[from] StunError),

    /// A wrapped IO error.
    #[error("{0}")]
    Io(#[from] io::Error),
}

/// Type of protocol used in [`Transmit`] and [`Receive`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// An outgoing packet
pub struct Transmit {
    /// This protocol the socket is using.
    pub proto: Protocol,

    /// The source socket this packet should be sent from.
    ///
    /// For ICE it's important to match up outgoing packets with source network interface.
    pub source: SocketAddr,

    /// This socket this datagram should be sent to.
    pub destination: SocketAddr,

    /// Contents of the datagram.
    pub contents: DatagramSend,
}

/// A wrapper for some payload that is to be sent.
#[derive(Debug)]
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

#[derive(Debug)]
/// Received incoming data.
pub struct Receive<'a> {
    /// The protocol the socket this received data originated from is using.
    pub proto: Protocol,

    /// The socket this received data originated from.
    pub source: SocketAddr,

    /// The destination ip of the datagram.
    pub destination: SocketAddr,

    /// Parsed contents of the datagram.
    pub contents: DatagramRecv<'a>,
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
pub enum DatagramRecv<'a> {
    #[doc(hidden)]
    Stun(StunMessage<'a>),
    #[doc(hidden)]
    Dtls(&'a [u8]),
    #[doc(hidden)]
    Rtp(&'a [u8]),
    #[doc(hidden)]
    Rtcp(&'a [u8]),
}

impl<'a> TryFrom<&'a [u8]> for DatagramRecv<'a> {
    type Error = NetError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        use DatagramRecv::*;

        let kind = MultiplexKind::try_from(value)?;

        Ok(match kind {
            MultiplexKind::Stun => Stun(StunMessage::parse(value)?),
            MultiplexKind::Dtls => Dtls(value),
            MultiplexKind::Rtp => Rtp(value),
            MultiplexKind::Rtcp => Rtcp(value),
        })
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
