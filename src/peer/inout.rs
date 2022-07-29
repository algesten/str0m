use std::convert::TryFrom;
use std::net::SocketAddr;
use std::ops::Deref;

use crate::sdp::{parse_sdp, Sdp};
use crate::stun::{self, StunMessage};
use crate::udp::UdpKind;
use crate::Error;

pub enum Input<'a> {
    Tick(&'a mut [u8]),
    Offer(Offer),
    Answer(Answer),
    Network(SocketAddr, NetworkData<'a>),
}

pub enum Output<'a> {
    Yield,
    NeedTick,
    Offer(Offer),
    Answer(Answer),
    Network(SocketAddr, NetworkData<'a>),
}

pub enum NetworkData<'a> {
    Stun(StunMessage<'a>),
}

pub struct Offer(pub(crate) Sdp);

pub struct Answer(pub(crate) Sdp);

impl<'a> From<Offer> for Input<'a> {
    fn from(v: Offer) -> Self {
        Input::Offer(v)
    }
}

impl<'a> From<Answer> for Input<'a> {
    fn from(v: Answer) -> Self {
        Input::Answer(v)
    }
}

impl<'a> From<Offer> for Output<'a> {
    fn from(v: Offer) -> Self {
        Output::Offer(v)
    }
}

impl<'a> From<Answer> for Output<'a> {
    fn from(v: Answer) -> Self {
        Output::Answer(v)
    }
}

impl<'a> From<()> for Output<'a> {
    fn from(_: ()) -> Self {
        Output::NeedTick
    }
}

impl<'a> From<(SocketAddr, NetworkData<'a>)> for Input<'a> {
    fn from((addr, data): (SocketAddr, NetworkData<'a>)) -> Self {
        Input::Network(addr, data)
    }
}

impl<'a> From<(SocketAddr, NetworkData<'a>)> for Output<'a> {
    fn from((addr, data): (SocketAddr, NetworkData<'a>)) -> Self {
        Output::Network(addr, data)
    }
}

impl<'a> From<StunMessage<'a>> for NetworkData<'a> {
    fn from(v: StunMessage<'a>) -> Self {
        NetworkData::Stun(v)
    }
}

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

impl<'a> TryFrom<&'a [u8]> for NetworkData<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let kind = UdpKind::try_from(value)?;

        Ok(match kind {
            UdpKind::Stun => NetworkData::Stun(stun::parse_message(&value)?),
            UdpKind::Dtls => todo!(),
            UdpKind::Rtp => todo!(),
            UdpKind::Rtcp => todo!(),
        })
    }
}
