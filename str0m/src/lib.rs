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
use stats::{MediaEgressStats, MediaIngressStats, PeerStats, Stats};
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
    pub use sctp::{ProtoError, SctpError};
    pub use sdp::SdpError;
}

pub mod channel;
use channel::{Channel, ChannelData, ChannelId};

pub mod media;
use media::{CodecConfig, Direction, KeyframeRequest};
use media::{KeyframeRequestKind, MediaChanged, MediaData};
use media::{Media, MediaAdded, Mid, Pt, Rid, Ssrc};

mod change;
pub use change::ChangeSet;

mod util;
pub(crate) use util::*;

mod session;
use session::{MediaEvent, Session};

mod session_sdp;
use session_sdp::AsSdpParams;

use crate::stats::StatsSnapshot;

pub mod stats;

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

    #[error("Direction does not allow sending: {0}")]
    NotSendingDirection(Direction),

    /// If MediaWriter.request_keyframe fails because we can't find an SSRC to use.
    #[error("No receiver source (rid: {0:?})")]
    NoReceiverSource(Option<Rid>),

    /// The keyframe request failed because the kind of request is not enabled
    /// by the SDP negotiation.
    #[error("Requested feedback is not enabled: {0:?}")]
    FeedbackNotEnabled(KeyframeRequestKind),

    /// Parser errors from network packet parsing.
    #[error("{0}")]
    Net(#[from] error::NetError),

    /// ICE agent errors.
    #[error("{0}")]
    Ice(#[from] error::IceError),

    /// SCTP (data channel engine) errors.
    #[error("{0}")]
    Sctp(#[from] error::SctpError),

    /// Some other error.
    #[error("{0}")]
    Other(String),
}

/// Instance that does WebRTC. Main struct of the entire library.
///
/// This is a [Sans I/O][1] implementation meaning the `Rtc` instance itself is not doing any network
/// talking. Furthermore it has no internal threads or async tasks. All operations are synchronously
/// happening from the calls of the public API.
///
/// Output from the instance can be grouped into three kinds.
///
/// 1. Events (such as receiving media or data channel data).
/// 2. Network output. Data to be sent, typically from a UDP socket.
/// 3. Timeouts. When the instance expects a time input.
///
/// Input to the `Rtc` instance is:
///
/// 1. User operations (such as sending media or data channel data).
/// 2. Network input. Typically read from a UDP socket.
/// 3. Timeouts. As obtained from the output above.
///
/// The correct use can be described like below (or seen in the examples).
/// The TODO lines is where the user would fill in their code.
///
/// ```no_run
/// # use str0m::{Rtc, Output, Input};
/// let mut rtc = Rtc::new();
///
/// loop {
///     let timeout = match rtc.poll_output().unwrap() {
///         Output::Timeout(v) => v,
///         Output::Transmit(t) => {
///             // TODO: Send data to remote peer.
///             continue; // poll again
///         }
///         Output::Event(e) => {
///             // TODO: Handle event.
///             continue; // poll again
///         }
///     };
///
///     // TODO: Wait for one of two events, reaching `timeout`
///     //       or receiving network input. Both are encapsualted
///     //       in the Input enum.
///     let input: Input = todo!();
///
///     rtc.handle_input(input).unwrap();
/// }
/// ```
///
/// [1]: https://sans-io.readthedocs.io
pub struct Rtc {
    alive: bool,
    ice: IceAgent,
    dtls: Dtls,
    setup: Setup,
    sctp: RtcSctp,
    stats: Stats,
    next_sctp_channel: u16,
    session: Session,
    remote_fingerprint: Option<Fingerprint>,
    pending: Option<Changes>,
    remote_addrs: Vec<SocketAddr>,
    send_addr: Option<SendAddr>,
    last_now: Instant,
    peer_bytes_rx: u64,
    peer_bytes_tx: u64,
}

struct SendAddr {
    source: SocketAddr,
    destination: SocketAddr,
}

/// Events produced by [`Rtc::poll_output()`].
#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// ICE connection state changes tells us whether the [`Rtc`] instance is
    /// connected to the peer or not.
    IceConnectionStateChange(IceConnectionState),

    /// Upon completing an SDP negotiation, and there are new m-lines. The lines
    /// are emitted.
    ///
    /// Upon this event, the [`Media`] instance is available via [`Rtc::media()`].
    MediaAdded(MediaAdded),

    /// Incoming media data sent by the remote peer.
    MediaData(MediaData),

    // Upon SDP renegotiation, a change event may be emitted.
    //
    // Currently only covers a change of direction.
    MediaChanged(MediaChanged),

    /// Incoming keyframe request for media that we are sending to the remote peer.
    ///
    /// The request is either PLI (Picture Loss Indication) or FIR (Full Intra Request).
    KeyframeRequest(KeyframeRequest),

    /// A data channel has opened. The first ever data channel results in an SDP
    /// negotiation, and this events comes at the end of that.
    ///
    /// The string is the channel label which is set by the opening peer and can
    /// be used to identify the purpose of the channel when there are more than one.
    ///
    /// The negotiation is to set up an SCTP association via DTLS. Subsequent data
    /// channels reuse the same association.
    ///
    /// Upon this event, the [`Channel`] can be obtained via [`Rtc::channel()`].
    ChannelOpen(ChannelId, String),

    /// Incoming data channel data from the remote peer.
    ChannelData(ChannelData),

    /// A data channel has been closed.
    ChannelClose(ChannelId),

    PeerStats(PeerStats),

    MediaIngressStats(MediaIngressStats),

    MediaEgressStats(MediaEgressStats),
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
    /// Creates a new instance with default settings.
    ///
    /// To configure the instance, use [`RtcConfig`].
    ///
    /// ```
    /// use str0m::Rtc;
    ///
    /// let rtc = Rtc::new();
    /// ```
    pub fn new() -> Self {
        let config = RtcConfig::default();
        Self::new_from_config(config)
    }

    /// Creates a config builder that configures an [`Rtc`] instance.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let rtc = Rtc::builder()
    ///     .ice_lite(true)
    ///     .build();
    /// ```
    pub fn builder() -> RtcConfig {
        RtcConfig::new()
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
            session: Session::new(config.codec_config, config.ice_lite),
            sctp: RtcSctp::new(),
            stats: Stats::new(),
            next_sctp_channel: 0, // Goes 0, 1, 2 for both DTLS server or client
            remote_fingerprint: None,
            pending: None,
            remote_addrs: vec![],
            send_addr: None,
            last_now: already_happened(),
            peer_bytes_rx: 0,
            peer_bytes_tx: 0,
        }
    }

    /// Tests if this instance is still working.
    ///
    /// Certain events will straight away disconnect the `Rtc` instance, such as
    /// the DTLS fingerprint from the SDP not matching that of the TLS negotiation
    /// (since that would potentially indicate a MITM attack!).
    ///
    /// The instance can be manually disconnected using [`Rtc::disconnect()`].
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let mut rtc = Rtc::new();
    ///
    /// assert!(rtc.is_alive());
    ///
    /// rtc.disconnect();
    /// assert!(!rtc.is_alive());
    /// ```
    pub fn is_alive(&self) -> bool {
        self.alive
    }

    /// Force disconnects the instance making [`Rtc::is_alive()`] return `false`.
    ///
    /// This makes [`Rtc::poll_output`] and [`Rtc::handle_input`] go inert and not
    /// produce anymore network output or events.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let mut rtc = Rtc::new();
    ///
    /// rtc.disconnect();
    /// assert!(!rtc.is_alive());
    /// ```
    pub fn disconnect(&mut self) {
        if self.alive {
            info!("Set alive=false");
            self.alive = false;
        }
    }

    /// Add a local ICE candidate. Local candidates are socket addresses the `Rtc` instance
    /// use for communicating with the peer.
    ///
    /// This library has no built-in discovery of local network addresses on the host
    /// or NATed addresses via a STUN server or TURN server. The user of the library
    /// is expected to add new local candidates as they are discovered.
    ///
    /// In WebRTC lingo, the `Rtc` instance is permanently in a mode of [Trickle Ice][1]. It's
    /// however advisable to add at least one local candidate before commencing SDP negotiation.
    ///
    /// ```
    /// # use str0m::{Rtc, Candidate};
    /// let mut rtc = Rtc::new();
    ///
    /// let a = "127.0.0.1:5000".parse().unwrap();
    /// let c = Candidate::host(a).unwrap();
    ///
    /// rtc.add_local_candidate(c);
    /// ```
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc8838.txt
    pub fn add_local_candidate(&mut self, c: Candidate) {
        self.ice.add_local_candidate(c);
    }

    /// Add a remote ICE candidate. Remote candidates are addresses of the peer.
    ///
    /// Remote candidates are typically added via receiving a remote [`Offer`] or [`Answer`].
    /// However for the case of [Trickle Ice][1], this is the way to add remote candidaes
    /// that are "trickled" from the other side.
    ///
    /// ```
    /// # use str0m::{Rtc, Candidate};
    /// let mut rtc = Rtc::new();
    ///
    /// let a = "1.2.3.4:5000".parse().unwrap();
    /// let c = Candidate::host(a).unwrap();
    ///
    /// rtc.add_remote_candidate(c);
    /// ```
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc8838.txt
    pub fn add_remote_candidate(&mut self, c: Candidate) {
        self.ice.add_remote_candidate(c);
    }

    /// Checks current connection state. This state is also obtained via
    /// [`Event::IceConnectionStateChange`].
    ///
    /// More details on connection states can be found in the [ICE RFC][1].
    /// ```
    /// # use str0m::{Rtc, IceConnectionState};
    /// let mut rtc = Rtc::new();
    ///
    /// assert_eq!(rtc.ice_connection_state(), IceConnectionState::New);
    /// ```
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc8445
    pub fn ice_connection_state(&self) -> IceConnectionState {
        self.ice.state()
    }

    /// Make changes to the Rtc session. This is the entry point for making an [`Offer`].
    /// The resulting [`ChangeSet`] encapsulates changes to the `Rtc` session that will
    /// require an SDP negotiation.
    ///
    /// The [`ChangeSet`] allows us to make multiple changes in one go. Calling
    /// [`ChangeSet::apply()`] doesn't apply the changes, but produces the [`Offer`]
    /// that is to be sent to the remote peer. Only when the the remote peer responds with
    /// an [`Answer`] can the changes be made to the session. The call to accept the answer
    /// is [`PendingChanges::accept_answer()`].
    ///
    /// How to send the [`Offer`] to the remote peer is not up to this library. Could be websocket,
    /// a data channel or some other method of communication. See examples for a combination
    /// of using `HTTP POST` and data channels.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// # use str0m::media::{MediaKind, Direction};
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.create_change_set();
    /// let mid_audio = changes.add_media(MediaKind::Audio, Direction::SendOnly, None);
    /// let mid_video = changes.add_media(MediaKind::Video, Direction::SendOnly, None);
    ///
    /// let offer = changes.apply().unwrap();
    /// let json = serde_json::to_vec(&offer).unwrap();
    /// ```
    pub fn create_change_set(&mut self) -> ChangeSet {
        ChangeSet::new(self)
    }

    /// Accept an [`Offer`] from the remote peer. If this call returns successfully, the
    /// changes will have been made to the session. The resulting [`Answer`] should be
    /// sent to the remote peer.
    ///
    /// <b>Note. [`Rtc::pending_changes()`] from a previous non-completed [`ChangeSet`] are
    /// rolled back when calling this function.</b>
    ///
    /// The incoming SDP is validated in various ways which can cause this call to fail.
    /// Example of such problems would be an SDP without any m-lines, missing `a=fingerprint`
    /// or if `a=group` doesn't match the number of m-lines.
    ///
    /// ```no_run
    /// # use str0m::{Rtc, Offer};
    ///  // obtain offer from remote peer.
    /// let json_offer: &[u8] = todo!();
    /// let offer: Offer = serde_json::from_slice(json_offer).unwrap();
    ///
    /// let mut rtc = Rtc::new();
    /// let answer = rtc.accept_offer(offer).unwrap();
    ///
    /// // send json_answer to remote peer.
    /// let json_answer = serde_json::to_vec(&answer).unwrap();
    /// ```
    pub fn accept_offer(&mut self, offer: Offer) -> Result<Answer, RtcError> {
        // rollback any pending offer.
        self.accept_answer(None)?;

        if offer.media_lines.is_empty() {
            return Err(RtcError::RemoteSdp("No m-lines in offer".into()));
        }

        self.add_ice_details(&offer)?;

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

    pub(crate) fn apply_direct_changes(&mut self, mut changes: Changes) {
        // Split out new channels, since that is not handled by the Session.
        let new_channels = changes.take_new_channels();

        for (id, dcep) in new_channels {
            self.sctp.open_stream(*id, dcep);
        }
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

    /// Obtain pending changes from a previous [`Rtc::create_change_set()`] call.
    /// The [`PendingChanges`] allows us to either accept a remote answer, or
    /// rollback the changes.
    ///
    /// When this function returns `None` there are no pending changes. Changes are
    /// automatically rolled back on [`Rtc::accept_offer()`]
    ///
    /// ```no_run
    /// # use str0m::{Rtc, Answer};
    /// # use str0m::media::{MediaKind, Direction};
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.create_change_set();
    /// let mid = changes.add_media(MediaKind::Audio, Direction::SendOnly, None);
    /// let offer = changes.apply().unwrap();
    ///
    /// // send offer to remote peer, receive answer back
    /// let answer: Answer = todo!();
    ///
    /// let pending = rtc.pending_changes().unwrap().accept_answer(answer);
    /// ```
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

            let mut pending = self.pending.take().expect("pending changes");

            // Split out new channels, since that is not handled by the Session.
            let new_channels = pending.take_new_channels();

            // Modify session with answer
            self.session.apply_answer(pending, answer)?;

            // Handle potentially new m=application line.
            self.init_sctp();

            for (id, dcep) in new_channels {
                self.sctp.open_stream(*id, dcep);
            }
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

    /// Poll the `Rtc` instance for output. Output can be three things, something to _Transmit_
    /// via a UDP socket (maybe via a TURN server). An _Event_, such as receiving media data,
    /// or a _Timeout_.
    ///
    /// The user of the library is expected to continuously call this function and deal with
    /// the output until it encounters an [`Output::Timeout`] at which point no further output
    /// is produced (if polled again, it will result in just another timeout).
    ///
    /// After exhausting the `poll_output`, the function will only produce more output again
    /// when one of two things happen:
    ///
    /// 1. The polled timeout is reached.
    /// 2. New network input.
    ///
    /// See [`Rtc`] instance documentation for how this is expected to be used in a loop.
    pub fn poll_output(&mut self) -> Result<Output, RtcError> {
        let o = self.do_poll_output()?;

        match &o {
            Output::Event(e) => match e {
                Event::ChannelData(_) | Event::MediaData(_) => trace!("{:?}", e),
                _ => debug!("{:?}", e),
            },
            Output::Transmit(t) => {
                self.peer_bytes_tx += t.contents.len() as u64;
                trace!("OUT {:?}", t)
            }
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

        while let Some(e) = self.sctp.poll() {
            match e {
                SctpEvent::Transmit(mut q) => {
                    if let Some(v) = q.front() {
                        if let Err(e) = self.dtls.handle_input(v) {
                            if e.is_would_block() {
                                self.sctp.push_back_transmit(q);
                                break;
                            } else {
                                return Err(e.into());
                            }
                        }
                        q.pop_front();
                        break;
                    }
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
                MediaEvent::Added(m) => Output::Event(Event::MediaAdded(m)),
                MediaEvent::Changed(m) => Output::Event(Event::MediaChanged(m)),
                MediaEvent::Data(m) => Output::Event(Event::MediaData(m)),
                MediaEvent::Error(e) => return Err(e),
                MediaEvent::KeyframeRequest(r) => Output::Event(Event::KeyframeRequest(r)),
            });
        }

        if let Some(e) = self.stats.poll_output() {
            return Ok(Output::Event(Event::PeerStats(e)));
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
            .soonest((self.sctp.poll_timeout(), "sctp"))
            .soonest((self.stats.poll_timeout(), "stats"));

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

    /// Check if this `Rtc` instance accepts the given input. This is used for demultiplexing
    /// several `Rtc` instances over the same UDP server socket.
    ///
    /// [`Input::Timeout`] is always accepted. [`Input::Receive`] is tested against the nominated
    /// ICE candidate. If that doesn't match and the incoming data is a STUN packet, the accept call
    /// is delegated to the ICE agent which recognises the remote peer from `a=ufrag`/`a=password`
    /// credentials negotiated in the SDP.
    ///
    /// In a server setup, the server would try to find an `Rtc` instances using [`Rtc::accepts()`].
    /// The first found instance would be given the input via [`Rtc::handle_input()`].
    ///
    /// ```no_run
    /// # use str0m::{Rtc, Input};
    /// // A vec holding the managed rtc instances. One instance per remote peer.
    /// let mut rtcs = vec![Rtc::new(), Rtc::new(), Rtc::new()];
    ///
    /// // Configure instances with local ice candidates etc.
    ///
    /// loop {
    ///     // TODO poll_timeout() and handle the output.
    ///
    ///     let input: Input = todo!(); // read network data from socket.
    ///     for rtc in &mut rtcs {
    ///         if rtc.accepts(&input) {
    ///             rtc.handle_input(input).unwrap();
    ///         }
    ///     }
    /// }
    /// ```
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

    /// Provide input to this `Rtc` instance. Input is either a [`Input::Timeout`] for some
    /// time that was previously obtained from [`Rtc::poll_output()`], or [`Input::Receive`]
    /// for network data.
    ///
    /// Both the timeout and the network data contains a [`std::time::Instant`] which drives
    /// time forward in the instance. For network data, the intention is to record the time
    /// of receiving the network data as precise as possible. This time is used to calculate
    /// things like jitter and bandwidth.
    ///
    /// It's always okay to call [`Rtc::handle_input()`] with a timeout, also before the
    /// time obtained via [`Rtc::poll_output()`].
    ///
    /// ```no_run
    /// # use str0m::{Rtc, Input};
    /// # use std::time::Instant;
    /// let mut rtc = Rtc::new();
    ///
    /// loop {
    ///     let timeout: Instant = todo!(); // rtc.poll_output() until we get a timeout.
    ///
    ///     let input: Input = todo!(); // wait for network data or timeout.
    ///     rtc.handle_input(input);
    /// }
    /// ```
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

    /// Get a [`Media`] instance for inspecting and manipulating media. Media has a 1-1
    /// relationship with "m-line" from the SDP. The `Media` instance is used for media
    /// regardless of current direction.
    ///
    /// Apart from inspecting information about the media, there are two fundamental
    /// operations. One is [`Media::writer()`] for writing outgoing media data, the other
    /// is [`Media::request_keyframe()`] to request a PLI/FIR keyframe for incoming media data.
    ///
    /// All media rows are announced via the [`Event::MediaAdded`] event. This function
    /// will return `None` for any [`Mid`] until that event has fired. This
    /// is also the case for the `mid` that comes from [`ChangeSet::add_media()`].
    ///
    /// Incoming media data is via the [`Event::MediaData`] event.
    ///
    /// ```no_run
    /// # use str0m::{Rtc, media::Mid};
    /// let mut rtc = Rtc::new();
    ///
    /// let mid: Mid = todo!(); // obtain Mid from Event::MediaAdded
    /// let media = rtc.media(mid).unwrap();
    /// // TODO write media or request keyframe.
    /// ```
    pub fn media(&mut self, mid: Mid) -> Option<&mut Media> {
        if !self.alive {
            return None;
        }
        self.session.get_media(mid)
    }

    fn do_handle_timeout(&mut self, now: Instant) {
        self.last_now = now;
        info!("timeout");
        self.ice.handle_timeout(now);
        self.sctp.handle_timeout(now);
        self.session.handle_timeout(now);
        // TODO: avoid this heavy operation if the timeout is not handled
        let snapshot = StatsSnapshot::from(self, now);
        self.stats.handle_timeout(snapshot);
    }

    fn do_handle_receive(&mut self, now: Instant, r: net::Receive) -> Result<(), RtcError> {
        trace!("IN {:?}", r);
        self.last_now = now;
        use net::DatagramRecv::*;

        let bytes_rx = match r.contents {
            // TODO: stun is already parsed (depacketized) here
            Stun(_) => 0,
            Dtls(v) | Rtp(v) | Rtcp(v) => v.len(),
        };

        // TODO: downgrade logging
        info!("peer connection bytes rx {} for {:?}", bytes_rx, r.contents);

        self.peer_bytes_rx += bytes_rx as u64;

        match r.contents {
            Stun(_) => self.ice.handle_receive(now, r),
            Dtls(_) => self.dtls.handle_receive(r)?,
            Rtp(_) | Rtcp(_) => self.session.handle_receive(now, r),
        }

        Ok(())
    }

    /// Obtain handle for writing to a data channel.
    ///
    /// This is first available when a [`ChannelId`] is advertised via [`Event::ChannelOpen`].
    /// The function returns `None` also for IDs from [`ChangeSet::add_channel()`].
    ///
    /// Incoming channel data is via the [`Event::ChannelData`] event.
    ///
    /// ```no_run
    /// # use str0m::{Rtc, channel::ChannelId};
    /// let mut rtc = Rtc::new();
    ///
    /// let cid: ChannelId = todo!(); // obtain Mid from Event::ChannelOpen
    /// let media = rtc.channel(cid).unwrap();
    /// // TODO write data channel data.
    /// ```
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

/// Customised config for creating an [`Rtc`] instance.
///
/// ```
/// use str0m::RtcConfig;
///
/// let rtc = RtcConfig::new()
///     .ice_lite(true)
///     .build();
/// ```
///
/// Configs implement [`Clone`] to help create multiple `Rtc` instances.
#[derive(Debug, Clone)]
pub struct RtcConfig {
    ice_lite: bool,
    codec_config: CodecConfig,
}

impl RtcConfig {
    /// Creates a new default config.
    pub fn new() -> Self {
        RtcConfig::default()
    }

    /// Toggle ice lite. Ice lite is a mode for WebRTC servers with public IP address.
    /// An [`Rtc`] instance in ice lite mode will not make STUN binding requests, but only
    /// answer to requests from the remote peer.
    ///
    /// See [ICE RFC][1]
    ///
    /// Defaults to `false`.
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc8445#page-13
    pub fn ice_lite(mut self, enabled: bool) -> Self {
        self.ice_lite = enabled;
        self
    }

    /// Clear all configured codecs.
    ///
    /// ```
    /// # use str0m::RtcConfig;
    ///
    /// // For the session to use only OPUS and VP8.
    /// let mut rtc = RtcConfig::default()
    ///     .clear_codecs()
    ///     .enable_opus()
    ///     .enable_vp8()
    ///     .build();
    /// ```
    pub fn clear_codecs(mut self) -> Self {
        self.codec_config.clear();
        self
    }

    /// Enable opus audio codec.
    ///
    /// Enabled by default.
    pub fn enable_opus(mut self) -> Self {
        self.codec_config.add_default_opus();
        self
    }

    /// Enable VP8 video codec.
    ///
    /// Enabled by default.
    pub fn enable_vp8(mut self) -> Self {
        self.codec_config.add_default_vp8();
        self
    }

    /// Enable H264 video codec.
    ///
    /// Enabled by default.
    pub fn enable_h264(mut self) -> Self {
        self.codec_config.add_default_h264();
        self
    }

    // TODO: AV1 depacketizer/packetizer.
    //
    // /// Enable AV1 video codec.
    // ///
    // /// Enabled by default.
    // pub fn enable_av1(mut self) -> Self {
    //     self.codec_config.add_default_av1();
    //     self
    // }

    /// Enable VP9 video codec.
    ///
    /// Enabled by default.
    pub fn enable_vp9(mut self) -> Self {
        self.codec_config.add_default_vp9();
        self
    }

    /// Lower level access to precis configuration of codecs (payload types).
    pub fn codec_config(&mut self) -> &mut CodecConfig {
        &mut self.codec_config
    }

    /// Create a [`Rtc`] from the configuration.
    pub fn build(self) -> Rtc {
        Rtc::new_from_config(self)
    }
}

impl Default for RtcConfig {
    fn default() -> Self {
        Self {
            ice_lite: Default::default(),
            codec_config: CodecConfig::new_with_defaults(),
        }
    }
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::IceConnectionStateChange(l0), Self::IceConnectionStateChange(r0)) => l0 == r0,
            (Self::MediaAdded(m0), Self::MediaAdded(m1)) => m0 == m1,
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
