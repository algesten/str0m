//!

#[macro_use]
extern crate tracing;

use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;

use ice::StunMessage;
use thiserror::Error;

mod id;

mod ice;
pub use ice::{Candidate, IceAgent, StunError};

mod sdp;
pub use sdp::SdpError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Stun(#[from] StunError),

    #[error("{0}")]
    Sdp(#[from] SdpError),

    #[error("{0}")]
    Io(#[from] io::Error),
}

/// An outgoing packet
pub struct Transmit {
    /// The source socket this packet should be sent from.
    ///
    /// For ICE it's important to match up outgoing packets with source network interface.
    pub source: SocketAddr,

    /// This socket this datagram should be sent to.
    pub destination: SocketAddr,

    /// Contents of the datagram.
    pub contents: Vec<u8>,
}

/// Received incoming data.
pub struct Receive<'a> {
    /// The socket this received data originated from.
    pub source: SocketAddr,

    /// The destination ip of the datagram.
    pub destination: SocketAddr,

    /// Parsed contents of the datagram.    
    pub contents: Datagram<'a>,
}

impl<'a> Receive<'a> {
    /// Creates a new instance by trying to parse the contents of `buf`.
    pub fn new(source: SocketAddr, destination: SocketAddr, buf: &'a [u8]) -> Result<Self, Error> {
        let contents = Datagram::try_from(buf)?;
        Ok(Receive {
            source,
            destination,
            contents,
        })
    }
}

pub enum Datagram<'a> {
    Stun(StunMessage<'a>),
}

impl<'a> TryFrom<&'a [u8]> for Datagram<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let kind = MultiplexKind::try_from(value)?;

        Ok(match kind {
            MultiplexKind::Stun => Datagram::Stun(StunMessage::parse(value)?),
            MultiplexKind::Dtls => todo!(),
            MultiplexKind::Rtp => todo!(),
            MultiplexKind::Rtcp => todo!(),
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
