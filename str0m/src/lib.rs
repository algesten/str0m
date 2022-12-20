#![allow(clippy::new_without_default)]

#[macro_use]
extern crate tracing;

use std::net::SocketAddr;
use std::time::Instant;
use std::{fmt, io};

use change::{Change, Changes};
use dtls::{Dtls, DtlsEvent, Fingerprint};
use ice::IceAgentEvent;
use ice::{IceAgent, IceError};
use net_::NetError;
use sctp::{RtcAssociation, SctpError, SctpEvent};
use sdp::{Sdp, Setup};
use thiserror::Error;

pub use ice::IceConnectionState;

pub use ice::Candidate;
pub use packet::RtpMeta;
pub use sctp::SctpData;
pub use sdp::{Answer, Offer};

pub mod net {
    pub use dtls::DtlsError;
    pub use net_::{DatagramRecv, DatagramSend, Receive, StunMessage, Transmit};
}

pub mod media;
use media::Media;

mod change;
pub use change::ChangeSet;

mod util;
pub(crate) use util::*;

mod session;
use session::{MediaEvent, Session};

mod session_sdp;
use session_sdp::AsSdpParams;

pub use rtp::{ChannelId, MediaTime, Mid, Pt, Ssrc};

/// Errors for the whole Rtc engine.
#[derive(Debug, Error)]
pub enum RtcError {
    /// Some problem with the remote SDP.
    #[error("remote sdp: {0}")]
    RemoteSdp(String),

    /// SDP errors.
    #[error("{0}")]
    Sdp(#[from] sdp::SdpError),

    /// RTP errors.
    #[error("{0}")]
    Rtp(#[from] rtp::RtpError),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),

    /// DTLS errors
    #[error("{0}")]
    Dtls(#[from] net::DtlsError),

    /// RTP packetization error
    #[error("{0} {1} {2}")]
    Packet(Mid, Pt, packet::PacketError),

    /// The PT attempted to write to is not known.
    #[error("PT is unknown {0}")]
    UnknownPt(Pt),

    /// If MediaWriter.write fails because the simulcast level
    /// used is not mapped to any SSRC.
    #[error("No sender source (simulcast level: {0}")]
    NoSenderSource(usize),

    #[error("{0}")]
    NetError(#[from] NetError),

    #[error("{0}")]
    IceError(#[from] IceError),

    #[error("{0}")]
    Sctp(#[from] SctpError),
}

/// Main type.
pub struct Rtc {
    alive: bool,
    ice: IceAgent,
    dtls: Dtls,
    setup: Setup,
    sctp: RtcAssociation,
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
pub enum Event {
    IceCandidate(Candidate),
    IceConnectionStateChange(IceConnectionState),
    MediaAdded(Mid),
    MediaData(MediaData),
    MediaError(RtcError),
    ChannelOpen(ChannelId, String),
    ChannelData(ChannelData),
    ChannelClose(ChannelId),
}

/// Video or audio data.
#[derive(PartialEq, Eq)]
pub struct MediaData {
    pub mid: Mid,
    pub pt: Pt,
    pub time: MediaTime,
    pub data: Vec<u8>,
    pub meta: Vec<RtpMeta>,
}

/// Data channel data.
#[derive(PartialEq, Eq)]
pub struct ChannelData {
    pub id: ChannelId,
    pub data: SctpData,
}

/// Network input as expected by [`Rtc::handle_input()`].
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
        Rtc {
            alive: true,
            ice: IceAgent::new(),
            dtls: Dtls::new().expect("DTLS to init without problem"),
            setup: Setup::ActPass,
            session: Session::new(),
            sctp: RtcAssociation::new(),
            next_sctp_channel: 0, // Goes 0, 1, 2 for both DTLS server or client
            remote_fingerprint: None,
            pending: None,
            remote_addrs: vec![],
            send_addr: None,
            last_now: already_happened(),
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

    pub fn create_offer(&mut self) -> ChangeSet {
        if !self.dtls.is_inited() {
            // The side that makes the first offer is the controlling side.
            self.ice.set_controlling(true);
        }

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
                self.alive = false;
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

        let params = self.as_sdp_params(false);
        let sdp = self.session.as_sdp(params);

        Ok(sdp.into())
    }

    pub(crate) fn set_changes(&mut self, changes: Changes) -> Offer {
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
                    self.alive = false;
                    return Err(RtcError::RemoteSdp("missing a=fingerprint".into()));
                }
            }

            // Modify session with answer
            let pending = self.pending.take().expect("pending changes");
            self.open_pending_data_channels(&pending)?;
            self.session.apply_answer(pending, answer)?;
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

        info!("DTLS setup is: {:?}", self.setup);
        assert!(self.setup != Setup::ActPass);

        if !self.dtls.is_inited() {
            let active = self.setup == Setup::Active;
            self.dtls.set_active(active);
            if active {
                self.dtls.handle_handshake()?;
            }
        }

        Ok(())
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

        if let Output::Event(e) = &o {
            info!("{:?}", e);
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
                IceAgentEvent::NewLocalCandidate(v) => {
                    return Ok(Output::Event(Event::IceCandidate(v)));
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
                            self.alive = false;
                            return Err(RtcError::RemoteSdp("remote fingerprint no match".into()));
                        }
                    } else {
                        self.alive = false;
                        return Err(RtcError::RemoteSdp("no a=fingerprint before dtls".into()));
                    }
                }
                DtlsEvent::Data(mut v) => {
                    self.sctp
                        .handle_input(sctp::SctpInput::Data(&mut v), self.last_now)?;
                }
            }
        }

        while let Some(e) = self.sctp.poll_event(self.last_now) {
            match e {
                SctpEvent::Open(id, dcep) => {
                    let id = id.into();
                    return Ok(Output::Event(Event::ChannelOpen(id, dcep.label)));
                }
                SctpEvent::Close(id) => {
                    let id = id.into();
                    return Ok(Output::Event(Event::ChannelClose(id)));
                }
                SctpEvent::Data(id, data) => {
                    let id = id.into();
                    let data = ChannelData { id, data };
                    return Ok(Output::Event(Event::ChannelData(data)));
                }
                SctpEvent::Transmit(data) => {
                    println!("YAY Attempt write DTLS");
                    if let Err(e) = self.dtls.handle_input(&data) {
                        println!("YAY Failed: {:?}", e);
                        if e.is_would_block() {
                            // hold back this transmit until dtls is ready for it.
                            self.sctp.push_back_transmit(data);
                            break;
                        }
                        return Err(e.into());
                    }
                    println!("YAY Success!");
                }
            }
        }

        if let Some(e) = self.session.poll_event() {
            match e {
                MediaEvent::MediaData(m) => {
                    return Ok(Output::Event(Event::MediaData(m)));
                }
                MediaEvent::MediaError(e) => return Ok(Output::Event(Event::MediaError(e))),
            }
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

        let time = None
            .soonest(self.ice.poll_timeout())
            .soonest(self.session.poll_timeout())
            .unwrap_or_else(not_happening);

        // We want to guarantee time doesn't go backwards.
        let next = if time < self.last_now {
            self.last_now
        } else {
            time
        };

        Ok(Output::Timeout(next))
    }

    pub fn handle_input(&mut self, input: Input) -> Result<(), RtcError> {
        if !self.alive {
            return Ok(());
        }

        match input {
            Input::Timeout(now) => self.do_handle_timeout(now),
            Input::Receive(now, r) => self.do_handle_receive(now, r)?,
        }
        Ok(())
    }

    pub fn media(&mut self, mid: Mid) -> Option<&mut Media> {
        self.session.get_media(mid)
    }

    /// Obtain handle for writing to a data channel.
    ///
    /// This is only available after either the remote peer has added one data channel
    /// to the SDP, or we've locally done [`ChangeSet::add_channel()`].
    ///
    /// Either way, we must wait for the [`Event::ChannelOpen`] before writing.
    pub fn channel(&mut self, id: ChannelId) -> Option<Channel<'_>> {
        // If the m=application isn't set up, we don't provide Channel
        self.session.app()?;

        if !self.sctp.is_open(*id) {
            return None;
        }

        Some(Channel { rtc: self, id })
    }

    fn do_handle_timeout(&mut self, now: Instant) {
        self.last_now = now;
        self.ice.handle_timeout(now);
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

    fn open_pending_data_channels(&mut self, pending: &Changes) -> Result<(), RtcError> {
        for p in &pending.0 {
            if let Change::AddChannel(id, dcep) = p {
                self.sctp.open_stream(**id, dcep)?;
            }
        }

        Ok(())
    }
}

pub struct Channel<'a> {
    rtc: &'a mut Rtc,
    id: ChannelId,
}

impl Channel<'_> {
    pub fn write(&mut self, binary: bool, buf: &[u8]) -> Result<usize, RtcError> {
        Ok(self.rtc.sctp.write(*self.id, binary, buf)?)
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

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::IceCandidate(l0), Self::IceCandidate(r0)) => l0 == r0,
            (Self::IceConnectionStateChange(l0), Self::IceConnectionStateChange(r0)) => l0 == r0,
            (Self::MediaAdded(l0), Self::MediaAdded(r0)) => l0 == r0,
            (Self::MediaData(m1), Self::MediaData(m2)) => m1 == m2,
            (Self::MediaError(_), Self::MediaError(_)) => false,
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
            .field("time", &self.time)
            .field("len", &self.data.len())
            .finish()
    }
}

impl fmt::Debug for ChannelData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelData")
            .field("id", &self.id)
            .field("data", &self.data)
            .finish()
    }
}
