use std::alloc::{Allocator, Global};
use std::fmt;
use std::net::SocketAddr;
use std::ops::Deref;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Type of protocol used in [`Transmit`].
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

/// An instruction to send an outgoing packet.
///
/// `A` is the allocator the contents are allocated from.
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = "DatagramSend<A>: Deserialize<'de>"))]
pub struct Transmit<A: Allocator = Global> {
    /// Protocol the transmission should use.
    pub proto: Protocol,

    /// The source IP this packet should be sent from.
    ///
    /// For ICE it's important to send outgoing packets from the correct IP address.
    /// The IP could come from a local socket or relayed over a TURN server. Features like
    /// hole-punching will only work if the packets are routed through the correct interfaces.
    pub source: SocketAddr,

    /// The destination address this datagram should be sent to.
    pub destination: SocketAddr,

    /// Contents of the datagram.
    pub contents: DatagramSend<A>,
}

impl<A: Allocator> fmt::Debug for Transmit<A> {
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
///
/// `A` is the allocator the payload is allocated from.
pub struct DatagramSend<A: Allocator = Global>(Vec<u8, A>);

impl<A: Allocator> From<Vec<u8, A>> for DatagramSend<A> {
    fn from(value: Vec<u8, A>) -> Self {
        DatagramSend(value)
    }
}

impl<A: Allocator> From<DatagramSend<A>> for Vec<u8, A> {
    fn from(value: DatagramSend<A>) -> Self {
        value.0
    }
}

impl<A: Allocator> Deref for DatagramSend<A> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<A: Allocator> fmt::Debug for DatagramSend<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DatagramSend").field(&self.0).finish()
    }
}

impl<A: Allocator> Serialize for DatagramSend<A> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_struct("DatagramSend", &self.0[..])
    }
}

impl<'de> Deserialize<'de> for DatagramSend {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename = "DatagramSend")]
        struct Wire(Vec<u8>);

        Wire::deserialize(deserializer).map(|w| DatagramSend(w.0))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const JSON: &str = r#"{"proto":"Udp","source":"1.1.1.1:1000","destination":"2.2.2.2:2000","contents":[1,2,3]}"#;

    #[test]
    fn transmit_serde_is_independent_of_the_allocator() {
        let source: SocketAddr = "1.1.1.1:1000".parse().unwrap();
        let destination: SocketAddr = "2.2.2.2:2000".parse().unwrap();

        let mut contents = Vec::new_in(&Global);
        contents.extend_from_slice(&[1, 2, 3]);
        let other_allocator = Transmit {
            proto: Protocol::Udp,
            source,
            destination,
            contents: contents.into(),
        };
        assert_eq!(serde_json::to_string(&other_allocator).unwrap(), JSON);

        let decoded: Transmit = serde_json::from_str(JSON).unwrap();
        assert_eq!(&*decoded.contents, [1, 2, 3]);
        assert_eq!(serde_json::to_string(&decoded).unwrap(), JSON);
    }
}
