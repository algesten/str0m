use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};

use crate::sdp::{parse_sdp, Sdp};
use crate::stun::{self, StunMessage};
use crate::udp::UdpKind;
use crate::{Error, UDP_MTU};

/// Encapsulates network input (typically from a UDP socket).
///
/// Cannot deal with partial data. Must be entire UDP packets at a time.
///
/// ```no_run
/// # use str0m::*;
/// # use std::convert::TryFrom;
/// # use std::net::SocketAddr;
/// # fn main() -> Result<(), Error> {
/// let data: &[u8] = todo!(); // obtain data from socket.
/// let addr: SocketAddr = todo!(); // address of data.
///
/// // This parses the input data, and it can throw an
/// // error if there are problems understanding the data.
/// let input = NetworkInput::try_from(data)?;
/// # Ok(())}
/// ```
pub struct NetworkInput<'a>(pub(crate) NetworkInputInner<'a>);

#[derive(Clone)]
pub(crate) enum NetworkInputInner<'a> {
    #[doc(hidden)]
    Stun(StunMessage<'a>),
    #[doc(hidden)]
    Dtls(&'a [u8]),
}

#[derive(Clone)]
pub struct NetworkOutput(Box<[u8; UDP_MTU]>, usize);

impl NetworkOutput {
    pub(crate) fn new() -> Self {
        NetworkOutput(Box::new([0_u8; UDP_MTU]), 0)
    }

    /// This provides _the entire_ buffer to write. `set_len` must be done on
    /// the writer onoce write is complete.
    pub(crate) fn into_writer(self) -> NetworkOutputWriter {
        NetworkOutputWriter(self, false)
    }
}

impl Deref for NetworkOutput {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[0..self.1]
    }
}

/// SDP offer.
#[derive(Debug)]
pub struct Offer(pub(crate) Sdp);

/// SDP answer.
#[derive(Debug)]
pub struct Answer(pub(crate) Sdp);

impl Deref for Offer {
    type Target = Sdp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for Answer {
    type Target = Sdp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> TryFrom<&'a str> for Offer {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let sdp = parse_sdp(value)?;
        Ok(Offer(sdp))
    }
}

impl<'a> TryFrom<&'a str> for Answer {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let sdp = parse_sdp(value)?;
        Ok(Answer(sdp))
    }
}

impl<'a> TryFrom<&'a [u8]> for NetworkInput<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let kind = UdpKind::try_from(value)?;

        Ok(NetworkInput(match kind {
            UdpKind::Stun => NetworkInputInner::Stun(stun::parse_message(&value)?),
            UdpKind::Dtls => NetworkInputInner::Dtls(value),
            UdpKind::Rtp => todo!(),
            UdpKind::Rtcp => todo!(),
        }))
    }
}

/// RAII guard for writing to [`NetworkOutput`].
pub(crate) struct NetworkOutputWriter(NetworkOutput, bool);

impl NetworkOutputWriter {
    #[must_use]
    pub fn set_len(mut self, len: usize) -> NetworkOutput {
        assert!(len <= self.0 .0.len());
        self.1 = true;
        self.0 .1 = len;
        self.0
    }
}

impl Deref for NetworkOutputWriter {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0 .0[..]
    }
}

impl DerefMut for NetworkOutputWriter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0 .0[..]
    }
}
