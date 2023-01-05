#![allow(clippy::new_without_default)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::assertions_on_constants)]

#[macro_use]
extern crate tracing;

use std::net::SocketAddr;
use std::time::Instant;
use std::{fmt, io};

use change::Changes;
use dtls::{Dtls, DtlsEvent, Fingerprint};
use ice::IceAgent;
use ice::IceAgentEvent;
use net_::DatagramRecv;
use sctp::{RtcSctp, SctpEvent};
use sdp::{Sdp, Setup};
use thiserror::Error;

pub use ice::IceConnectionState;

pub use ice::Candidate;
pub use sdp::{Answer, Offer};

/// Network related types to get socket data in/out of [`Rtc`].
pub mod net {
    pub use net_::{DatagramRecv, DatagramSend, Receive, Transmit};
}

/// Various error types.
pub mod error {
    pub use dtls::DtlsError;
    pub use ice::IceError;
    pub use net_::NetError;
    pub use packet::PacketError;
    pub use rtp::RtpError;
    pub use sctp::SctpError;
    pub use sdp::SdpError;
}

pub mod channel;
use channel::{Channel, ChannelData, ChannelId};

pub mod media;
use media::{CodecConfig, Direction, KeyframeRequest, MediaData};
use media::{Media, MediaKind, Mid, Pt, Rid, Ssrc};

mod change;
pub use change::ChangeSet;

mod util;
pub(crate) use util::*;

mod session;
use session::{MediaEvent, Session};

mod session_sdp;
use session_sdp::AsSdpParams;

/// Errors for the whole Rtc engine.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RtcError {
    /// Some problem with the remote SDP.
    #[error("remote sdp: {0}")]
    RemoteSdp(String),

    /// SDP errors.
    #[error("{0}")]
    Sdp(#[from] error::SdpError),

    /// RTP errors.
    #[error("{0}")]
    Rtp(#[from] error::RtpError),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),

    /// DTLS errors
    #[error("{0}")]
    Dtls(#[from] error::DtlsError),

    /// RTP packetization error
    #[error("{0} {1} {2}")]
    Packet(Mid, Pt, error::PacketError),

    /// The PT attempted to write to is not known.
    #[error("PT is unknown {0}")]
    UnknownPt(Pt),

    /// If MediaWriter.write fails because we can't find an SSRC to use.
    #[error("No sender source")]
    NoSenderSource,

    /// If MediaWriter.request_keyframe fails because we can't find an SSRC to use.
    #[error("No receiver source (rid: {0:?})")]
    NoReceiverSource(Option<Rid>),

    #[error("{0}")]
    Net(#[from] error::NetError),

    #[error("{0}")]
    Ice(#[from] error::IceError),

    #[error("{0}")]
    Sctp(#[from] error::SctpError),

    #[error("{0}")]
    Other(String),
}

/// Instance that does WebRTC. Main struct of the entire lib.
pub struct Rtc {
    alive: bool,
    ice: IceAgent,
    dtls: Dtls,
    setup: Setup,
    sctp: RtcSctp,
    next_sctp_channel: u16,
    session: Session,
    remote_fingerprint: Option<Fingerprint>,
    pending: Option<Changes>,
    remote_addrs: Vec<SocketAddr>,
    send_addr: Option<SendAddr>,
    last_now: Instant,
}

struct SendAddr {
    source: SocketAddr,
    destination: SocketAddr,
}

/// Events produced by [`Rtc::poll_output()`]
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    IceConnectionStateChange(IceConnectionState),
    MediaAdded(Mid, MediaKind, Direction),
    MediaData(MediaData),
    KeyframeRequest(KeyframeRequest),
    ChannelOpen(ChannelId, String),
    ChannelData(ChannelData),
    ChannelClose(ChannelId),
}

/// Input as expected by [`Rtc::handle_input()`]. Either network data or a timeout.
#[derive(Debug)]
pub enum Input<'a> {
    Timeout(Instant),
    Receive(Instant, net::Receive<'a>),
}

/// Output produced by [`Rtc::poll_output()`]
pub enum Output {
    Timeout(Instant),
    Transmit(net::Transmit),
    Event(Event),
}

impl Rtc {
    pub fn new() -> Self {
        let config = RtcConfig::default();
        Self::new_from_config(config)
    }

    pub(crate) fn new_from_config(config: RtcConfig) -> Self {
        let mut ice = IceAgent::new();

        if config.ice_lite {
            ice.set_ice_lite(config.ice_lite);
        }

        Rtc {
            alive: true,
            ice,
            dtls: Dtls::new().expect("DTLS to init without problem"),
            setup: Setup::ActPass,
            session: Session::new(config.codec_config),
            sctp: RtcSctp::new(),
            next_sctp_channel: 0, // Goes 0, 1, 2 for both DTLS server or client
            remote_fingerprint: None,
            pending: None,
            remote_addrs: vec![],
            send_addr: None,
            last_now: already_happened(),
        }
    }

    pub fn is_alive(&self) -> bool {
        self.alive
    }

    pub fn disconnect(&mut self) {
        if self.alive {
            info!("Set alive=false");
            self.alive = false;
        }
    }

    pub fn add_local_candidate(&mut self, c: Candidate) {
        self.ice.add_local_candidate(c);
    }

    pub fn add_remote_candidate(&mut self, c: Candidate) {
        self.ice.add_remote_candidate(c);
    }

    pub fn ice_connection_state(&self) -> IceConnectionState {
        self.ice.state()
    }

    pub fn create_change_set(&mut self) -> ChangeSet {
        ChangeSet::new(self)
    }

    pub fn accept_offer(&mut self, offer: Offer) -> Result<Answer, RtcError> {
        if offer.media_lines.is_empty() {
            return Err(RtcError::RemoteSdp("No m-lines in offer".into()));
        }

        self.add_ice_details(&offer)?;

        // rollback any pending offer.
        self.accept_answer(None)?;

        if self.remote_fingerprint.is_none() {
            if let Some(f) = offer.fingerprint() {
                self.remote_fingerprint = Some(f);
            } else {
                self.disconnect();
                return Err(RtcError::RemoteSdp("missing a=fingerprint".into()));
            }
        }

        if !self.dtls.is_inited() {
            // The side that makes the first offer is the controlling side.
            self.ice.set_controlling(false);
        }

        // If we receive an offer, we are not allowed to answer with actpass.
        if self.setup == Setup::ActPass {
            let remote_setup = offer.setup().unwrap_or(Setup::Active);
            self.setup = if remote_setup == Setup::ActPass {
                Setup::Passive
            } else {
                remote_setup.invert()
            };
            debug!(
                "Change setup for answer: {} -> {}",
                Setup::ActPass,
                self.setup
            );
        }

        // Ensure setup=active/passive is corresponding remote and init dtls.
        self.init_setup_dtls(&offer)?;

        // Modify session with offer
        self.session.apply_offer(offer)?;

        // Handle potentially new m=application line.
        self.init_sctp();

        let params = self.as_sdp_params(false);
        let sdp = self.session.as_sdp(params);

        Ok(sdp.into())
    }

    pub(crate) fn set_pending(&mut self, changes: Changes) -> Offer {
        if !self.dtls.is_inited() {
            // The side that makes the first offer is the controlling side.
            self.ice.set_controlling(true);
        }

        self.pending = Some(changes);

        let params = self.as_sdp_params(true);
        let sdp = self.session.as_sdp(params);

        sdp.into()
    }

    fn as_sdp_params(&self, include_pending: bool) -> AsSdpParams {
        AsSdpParams {
            candidates: self.ice.local_candidates(),
            creds: self.ice.local_credentials(),
            fingerprint: self.dtls.local_fingerprint(),
            setup: self.setup,
            pending: if include_pending {
                &self.pending
            } else {
                &None
            },
        }
    }

    pub fn pending_changes(&mut self) -> Option<PendingChanges> {
        if !self.alive {
            return None;
        }
        self.pending.as_ref()?;
        Some(PendingChanges { rtc: self })
    }

    fn accept_answer(&mut self, answer: Option<Answer>) -> Result<(), RtcError> {
        if let Some(answer) = answer {
            self.add_ice_details(&answer)?;

            // Ensure setup=active/passive is corresponding remote and init dtls.
            self.init_setup_dtls(&answer)?;

            if self.remote_fingerprint.is_none() {
                if let Some(f) = answer.fingerprint() {
                    self.remote_fingerprint = Some(f);
                } else {
                    self.disconnect();
                    return Err(RtcError::RemoteSdp("missing a=fingerprint".into()));
                }
            }

            // Modify session with answer
            let pending = self.pending.take().expect("pending changes");
            self.session.apply_answer(pending, answer, &mut self.sctp)?;

            // Handle potentially new m=application line.
            self.init_sctp();
        } else {
            // rollback
            self.pending = None;
        }

        Ok(())
    }

    fn add_ice_details(&mut self, sdp: &Sdp) -> Result<(), RtcError> {
        if let Some(creds) = sdp.ice_creds() {
            self.ice.set_remote_credentials(creds);
        } else {
            return Err(RtcError::RemoteSdp("missing a=ice-ufrag/pwd".into()));
        }

        for r in sdp.ice_candidates() {
            self.ice.add_remote_candidate(r.clone());
        }

        Ok(())
    }

    fn init_setup_dtls(&mut self, remote_sdp: &Sdp) -> Result<(), RtcError> {
        if let Some(remote_setup) = remote_sdp.setup() {
            self.setup = self.setup.compare_to_remote(remote_setup).ok_or_else(|| {
                RtcError::RemoteSdp(format!(
                    "impossible setup {:?} != {:?}",
                    self.setup, remote_setup
                ))
            })?;
        } else {
            warn!("Missing a=setup line");
        }

        if !self.dtls.is_inited() {
            info!("DTLS setup is: {:?}", self.setup);
            assert!(self.setup != Setup::ActPass);

            let active = self.setup == Setup::Active;
            self.dtls.set_active(active);
            if active {
                self.dtls.handle_handshake()?;
            }
        }

        Ok(())
    }

    fn init_sctp(&mut self) {
        // If we got an m=application line, ensure we have negotiated the
        // SCTP association with the other side.
        if self.session.app().is_some() && !self.sctp.is_inited() {
            self.sctp.init(self.setup == Setup::Active, self.last_now);
        }
    }

    /// Creates a new Mid that is not in the session already.
    pub(crate) fn new_mid(&self) -> Mid {
        loop {
            let mid = Mid::new();
            if !self.session.has_mid(mid) {
                break mid;
            }
        }
    }

    /// Creates the new SCTP channel.
    pub(crate) fn new_sctp_channel(&mut self) -> ChannelId {
        let active = self.setup == Setup::Active;
        // RFC 8831
        // Unless otherwise defined or negotiated, the
        // streams are picked based on the DTLS role (the client picks even
        // stream identifiers, and the server picks odd stream identifiers).
        let id = self.next_sctp_channel * 2 + if active { 0 } else { 1 };
        self.next_sctp_channel += 1;
        id.into()
    }

    /// Creates an Ssrc that is not in the session already.
    pub(crate) fn new_ssrc(&self) -> Ssrc {
        self.session.new_ssrc()
    }

    pub fn poll_output(&mut self) -> Result<Output, RtcError> {
        let o = self.do_poll_output()?;

        match &o {
            Output::Event(e) => debug!("{:?}", e),
            Output::Transmit(t) => trace!("OUT {:?}", t),
            Output::Timeout(_t) => {}
        }

        Ok(o)
    }

    fn do_poll_output(&mut self) -> Result<Output, RtcError> {
        if !self.alive {
            return Ok(Output::Timeout(not_happening()));
        }

        while let Some(e) = self.ice.poll_event() {
            match e {
                IceAgentEvent::IceRestart(_) => {
                    //
                }
                IceAgentEvent::IceConnectionStateChange(v) => {
                    return Ok(Output::Event(Event::IceConnectionStateChange(v)))
                }
                IceAgentEvent::DiscoveredRecv { source } => {
                    info!("ICE remote address: {:?}", source);
                    self.remote_addrs.push(source);
                    while self.remote_addrs.len() > 20 {
                        self.remote_addrs.remove(0);
                    }
                }
                IceAgentEvent::NominatedSend {
                    source,
                    destination,
                } => {
                    info!("ICE nominated send: {:?}", source);
                    self.send_addr = Some(SendAddr {
                        source,
                        destination,
                    });
                }
            }
        }

        while let Some(e) = self.dtls.poll_event() {
            match e {
                DtlsEvent::Connected => {
                    debug!("DTLS connected");
                }
                DtlsEvent::SrtpKeyingMaterial(mat) => {
                    info!("DTLS set SRTP keying material");
                    assert!(self.setup != Setup::ActPass);
                    let active = self.setup == Setup::Active;
                    self.session.set_keying_material(mat, active);
                }
                DtlsEvent::RemoteFingerprint(v1) => {
                    debug!("DTLS verify remote fingerprint");
                    if let Some(v2) = &self.remote_fingerprint {
                        if v1 != *v2 {
                            self.disconnect();
                            return Err(RtcError::RemoteSdp("remote fingerprint no match".into()));
                        }
                    } else {
                        self.disconnect();
                        return Err(RtcError::RemoteSdp("no a=fingerprint before dtls".into()));
                    }
                }
                DtlsEvent::Data(v) => {
                    self.sctp.handle_input(self.last_now, &v);
                }
            }
        }

        'outer: while let Some(e) = self.sctp.poll() {
            match e {
                SctpEvent::Transmit(mut q) => {
                    while let Some(v) = q.front() {
                        if let Err(e) = self.dtls.handle_input(v) {
                            if e.is_would_block() {
                                self.sctp.push_back_transmit(q);
                                break 'outer;
                            } else {
                                return Err(e.into());
                            }
                        }
                        q.pop_front();
                    }
                    continue;
                }
                SctpEvent::Open(id, dcep) => {
                    return Ok(Output::Event(Event::ChannelOpen(id.into(), dcep.label)));
                }
                SctpEvent::Close(id) => {
                    return Ok(Output::Event(Event::ChannelClose(id.into())));
                }
                SctpEvent::Data(id, binary, data) => {
                    let cd = ChannelData {
                        id: id.into(),
                        binary,
                        data,
                    };
                    return Ok(Output::Event(Event::ChannelData(cd)));
                }
            }
        }

        if let Some(e) = self.session.poll_event() {
            return Ok(match e {
                MediaEvent::Open(mid, kind, dir) => {
                    Output::Event(Event::MediaAdded(mid, kind, dir))
                }
                MediaEvent::Data(m) => Output::Event(Event::MediaData(m)),
                MediaEvent::Error(e) => return Err(e),
                MediaEvent::KeyframeRequest(r) => Output::Event(Event::KeyframeRequest(r)),
            });
        }

        if let Some(v) = self.ice.poll_transmit() {
            return Ok(Output::Transmit(v));
        }

        if let Some(send) = &self.send_addr {
            // These can only be sent after we got an ICE connection.
            let datagram = None
                .or_else(|| self.dtls.poll_datagram())
                .or_else(|| self.session.poll_datagram(self.last_now));

            if let Some(contents) = datagram {
                let t = net::Transmit {
                    source: send.source,
                    destination: send.destination,
                    contents,
                };
                return Ok(Output::Transmit(t));
            }
        }

        let time_and_reason = (None, "<not happening>")
            .soonest((self.ice.poll_timeout(), "ice"))
            .soonest((self.session.poll_timeout(), "session"))
            .soonest((self.sctp.poll_timeout(), "sctp"));

        // trace!("poll_output timeout reason: {}", time_and_reason.1);

        let time = time_and_reason.0.unwrap_or_else(not_happening);

        // We want to guarantee time doesn't go backwards.
        let next = if time < self.last_now {
            self.last_now
        } else {
            time
        };

        Ok(Output::Timeout(next))
    }

    pub fn accepts(&self, input: &Input) -> bool {
        let Input::Receive(_, r) = input else {
            // always accept the Input::Timeout.
            return true;
        };

        // This should cover Dtls, Rtp and Rtcp
        if let Some(send_addr) = &self.send_addr {
            // TODO: This assume symmetrical routing, i.e. we are getting
            // the incoming traffic from a remote peer from the same socket address
            // we've nominated for sending via the ICE agent.
            if r.source == send_addr.destination {
                return true;
            }
        }

        // STUN can use the ufrag/password to identify that a message belongs
        // to this Rtc instance.
        if let DatagramRecv::Stun(v) = &r.contents {
            return self.ice.accepts_message(v);
        }

        false
    }

    pub fn handle_input(&mut self, input: Input) -> Result<(), RtcError> {
        if !self.alive {
            return Ok(());
        }

        match input {
            Input::Timeout(now) => self.do_handle_timeout(now),
            Input::Receive(now, r) => {
                self.do_handle_receive(now, r)?;
                self.do_handle_timeout(now);
            }
        }
        Ok(())
    }

    pub fn media(&mut self, mid: Mid) -> Option<&mut Media> {
        if !self.alive {
            return None;
        }
        self.session.get_media(mid)
    }

    fn do_handle_timeout(&mut self, now: Instant) {
        self.last_now = now;
        self.ice.handle_timeout(now);
        self.sctp.handle_timeout(now);
        self.session.handle_timeout(now);
    }

    fn do_handle_receive(&mut self, now: Instant, r: net::Receive) -> Result<(), RtcError> {
        trace!("IN {:?}", r);
        self.last_now = now;
        use net::DatagramRecv::*;
        match r.contents {
            Stun(_) => self.ice.handle_receive(now, r),
            Dtls(_) => self.dtls.handle_receive(r)?,
            Rtp(_) | Rtcp(_) => self.session.handle_receive(now, r),
        }

        Ok(())
    }

    /// Obtain handle for writing to a data channel.
    ///
    /// This is only available after either the remote peer has added one data channel
    /// to the SDP, or we've locally done [`ChangeSet::add_channel()`].
    ///
    /// Either way, we must wait for the [`Event::ChannelOpen`] before writing.
    pub fn channel(&mut self, id: ChannelId) -> Option<Channel<'_>> {
        if !self.alive {
            return None;
        }

        // If the m=application isn't set up, we don't provide Channel
        self.session.app()?;

        if !self.sctp.is_open(*id) {
            return None;
        }

        Some(Channel::new(id, self))
    }
}

/// Changes waiting to be applied to the [`Rtc`].
pub struct PendingChanges<'a> {
    rtc: &'a mut Rtc,
}

impl<'a> PendingChanges<'a> {
    pub fn accept_answer(self, answer: Answer) -> Result<(), RtcError> {
        self.rtc.accept_answer(Some(answer))
    }

    pub fn rollback(self) {
        self.rtc.accept_answer(None).expect("rollback to not error");
    }
}

#[derive(Debug, Clone, Default)]
pub struct RtcConfig {
    ice_lite: bool,
    codec_config: CodecConfig,
}

impl RtcConfig {
    pub fn new() -> Self {
        RtcConfig::default()
    }

    pub fn ice_lite(mut self, enabled: bool) -> Self {
        self.ice_lite = enabled;
        self
    }

    pub fn enable_opus(mut self) -> Self {
        self.codec_config.add_default_opus();
        self
    }

    pub fn enable_vp8(mut self) -> Self {
        self.codec_config.add_default_vp8();
        self
    }

    pub fn enable_h264(mut self) -> Self {
        self.codec_config.add_default_h264();
        self
    }

    pub fn enable_av1(mut self) -> Self {
        self.codec_config.add_default_av1();
        self
    }

    pub fn enable_vp9(mut self) -> Self {
        self.codec_config.add_default_vp9();
        self
    }

    pub fn build(self) -> Rtc {
        Rtc::new_from_config(self)
    }
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::IceConnectionStateChange(l0), Self::IceConnectionStateChange(r0)) => l0 == r0,
            (Self::MediaAdded(l0, l1, l2), Self::MediaAdded(r0, r1, r2)) => {
                l0 == r0 && l1 == r1 && l2 == r2
            }
            (Self::MediaData(m1), Self::MediaData(m2)) => m1 == m2,
            (Self::ChannelOpen(l0, l1), Self::ChannelOpen(r0, r1)) => l0 == r0 && l1 == r1,
            (Self::ChannelData(l0), Self::ChannelData(r0)) => l0 == r0,
            (Self::ChannelClose(l0), Self::ChannelClose(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Eq for Event {}

impl fmt::Debug for MediaData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediaData")
            .field("mid", &self.mid)
            .field("pt", &self.pt)
            .field("rid", &self.rid)
            .field("time", &self.time)
            .field("len", &self.data.len())
            .finish()
    }
}

impl fmt::Debug for Rtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rtc").finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rtc_is_send() {
        fn is_send<T: Send>(_t: T) {}
        fn is_sync<T: Sync>(_t: T) {}
        is_send(Rtc::new());
        is_sync(Rtc::new());
    }
}
