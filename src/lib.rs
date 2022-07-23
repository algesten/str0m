#[macro_use]
extern crate tracing;

mod error;
mod sdp;
mod sdp_parse;
mod stun;
mod udp;
mod util;

use std::collections::HashSet;
use std::convert::TryFrom;
use std::net::SocketAddr;

pub use error::Error;
use sdp::{Answer, Fingerprint, IceCreds, Offer};
use stun::StunMessage;
use udp::UdpKind;
use util::Ts;

pub struct Peer {
    /// Remote credentials for STUN. Obtained from SDP.
    remote_creds: Vec<IceCreds>,

    /// Local credentials for STUN. We use one set for all m-lines.
    local_creds: IceCreds,

    /// Remote fingerprints for DTLS. Obtained from SDP.
    remote_fingerprints: Vec<Fingerprint>,

    /// Local fingerprint for DTLS. We use one certificate per peer.
    local_fingerprint: Fingerprint,

    /// Addresses that have been "unlocked" via STUN. These IP:PORT combos
    /// are now verified for other kinds of data like DTLS, RTP, RTCP...
    verified: HashSet<SocketAddr>,
}

impl Peer {
    pub fn accepts(&self, addr: SocketAddr, input: &Input<'_>) -> Result<bool, Error> {
        use Input::*;
        match input {
            Tick(_) => Ok(true),
            Offer(_) => Ok(true),
            Answer(_) => Ok(true),
            Stun(stun) => self.accepts_stun(addr, stun),
        }
    }

    pub fn handle_input<'a>(
        &mut self,
        ts: Ts,
        addr: SocketAddr,
        input: Input<'a>,
    ) -> Result<Output<'a>, Error> {
        use Input::*;
        Ok(match input {
            Tick(buf) => Output::Yield,
            Offer(v) => self.handle_offer(v)?.into(),
            Answer(v) => self.handle_answer(v)?.into(),
            Stun(stun) => self.handle_stun(addr, stun)?.into(),
        })
    }

    fn accepts_stun(&self, addr: SocketAddr, stun: &StunMessage<'_>) -> Result<bool, Error> {
        let (local_username, remote_username) = stun.local_remote_username();

        let remote_creds_has_username = self
            .remote_creds
            .iter()
            .any(|c| c.username == remote_username);

        if !remote_creds_has_username {
            // this is not a fault, the packet might not be for this peer.
            return Ok(false);
        }

        if local_username != self.local_creds.username {
            // this is a bit suspicious... maybe a name clash on the remote username?
            return Err(Error::StunError(format!(
                "STUN local != peer.local ({}): {} != {}",
                addr, local_username, self.local_creds.username
            )));
        }

        if !stun.check_integrity(&self.local_creds.password) {
            // this is also sus.
            return Err(Error::StunError(format!(
                "STUN check_integrity failed ({})",
                addr,
            )));
        }

        Ok(true)
    }

    fn handle_offer(&mut self, offer: Offer) -> Result<Answer, Error> {
        todo!()
    }

    fn handle_answer(&mut self, offer: Answer) -> Result<(), Error> {
        todo!()
    }

    fn handle_stun<'a>(
        &mut self,
        addr: SocketAddr,
        stun: StunMessage<'a>,
    ) -> Result<StunMessage<'a>, Error> {
        let reply = stun.reply()?;

        // on the back of a successful (authenticated) stun bind, we update
        // the validated addresses to receive dtls, rtcp, rtp etc.
        if self.verified.insert(addr) {
            trace!("STUN new verified peer ({})", addr);
        }

        Ok(reply)
    }
}

pub enum Input<'a> {
    Tick(&'a mut [u8]),
    Offer(Offer),
    Answer(Answer),
    Stun(StunMessage<'a>),
}

pub enum Output<'a> {
    Yield,
    NeedTick,
    Offer(Offer),
    Answer(Answer),
    Stun(StunMessage<'a>),
}

impl<'a> TryFrom<&'a [u8]> for Input<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let kind = UdpKind::try_from(value)?;

        Ok(match kind {
            UdpKind::Stun => Input::Stun(stun::parse_message(&value)?),
            UdpKind::Dtls => todo!(),
            UdpKind::Rtp => todo!(),
            UdpKind::Rtcp => todo!(),
        })
    }
}

impl<'a> From<StunMessage<'a>> for Input<'a> {
    fn from(v: StunMessage<'a>) -> Self {
        Input::Stun(v)
    }
}

impl<'a> From<StunMessage<'a>> for Output<'a> {
    fn from(v: StunMessage<'a>) -> Self {
        Output::Stun(v)
    }
}

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
