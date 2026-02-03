//! Network I/O types and STUN protocol implementation.

use std::net::SocketAddr;

pub use crate::stun::{StunMessage, TransId};
pub use str0m_proto::{Protocol, TcpType, Transmit};

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
