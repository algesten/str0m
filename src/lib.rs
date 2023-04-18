//! <image src="https://user-images.githubusercontent.com/227204/226143511-66fe5264-6ab7-47b9-9551-90ba7e155b96.svg" alt="str0m logo" ></image>
//!
//! A synchronous sans I/O WebRTC implementation in Rust.
//!
//! This is a [Sans I/O][sansio] implementation meaning the `Rtc` instance itself is not doing any network
//! talking. Furthermore it has no internal threads or async tasks. All operations are synchronously
//! happening from the calls of the public API.
//!
//! # Join us
//!
//! We are discussing str0m things on Zulip. Join us using this [invitation link][zulip].
//!
//! <image width="300px" src="https://user-images.githubusercontent.com/227204/209446544-f8a8d673-cb1b-4144-a0f2-42307b8d8869.gif" alt="silly clip showing video playing" ></image>
//!
//! # Usage
//!
//! The [`http-post`][x-post] example roughly illustrates how to receive
//! media data from a browser client. The example is single threaded and
//! a good starting point to understand the API.
//!
//! The [`chat`][x-chat] example shows how to connect multiple browsers
//! together and act as an SFU (Signal Forwarding Unit). The example
//! multiplexes all traffic over one server UDP socket and uses two threads
//! (one for the web server, and one for the SFU loop).
//!
//! ## Passive
//!
//! For passive connections, i.e. where the media and initial OFFER is
//! made by a remote peer, we need these steps to open the connection.
//!
//! ```no_run
//! # use str0m::{Rtc, Candidate};
//! // Instantiate a new Rtc instance.
//! let mut rtc = Rtc::new();
//!
//! //  Add some ICE candidate such as a locally bound UDP port.
//! let addr = "1.2.3.4:5000".parse().unwrap();
//! let candidate = Candidate::host(addr).unwrap();
//! rtc.add_local_candidate(candidate);
//!
//! // Accept an incoming offer from the remote peer
//! // and get the corresponding answer.
//! let offer = todo!();
//! let answer = rtc.sdp_api().accept_offer(offer).unwrap();
//!
//! // Forward the answer to the remote peer.
//!
//! // Go to _run loop_
//! ```
//!
//! ## Active
//!
//! Active connections means we are making the inital OFFER and waiting for a
//! remote ANSWER to start the connection.
//!
//! ```no_run
//! # use str0m::{Rtc, Candidate};
//! # use str0m::media::{MediaKind, Direction};
//! #
//! // Instantiate a new Rtc instance.
//! let mut rtc = Rtc::new();
//!
//! // Add some ICE candidate such as a locally bound UDP port.
//! let addr = "1.2.3.4:5000".parse().unwrap();
//! let candidate = Candidate::host(addr).unwrap();
//! rtc.add_local_candidate(candidate);
//!
//! // Create a `SdpApi`. The change lets us make multiple changes
//! // before sending the offer.
//! let mut change = rtc.sdp_api();
//!
//! // Do some change. A valid OFFER needs at least one "m-line" (media).
//! let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
//!
//! // Get the offer.
//! let (offer, pending) = change.apply().unwrap();
//!
//! // Forward the offer to the remote peer and await the answer.
//! // How to transfer this is outside the scope for this library.
//! let answer = todo!();
//!
//! // Apply answer.
//! rtc.sdp_api().accept_answer(pending, answer).unwrap();
//!
//! // Go to _run loop_
//! ```
//!
//! ## Run loop
//!
//! Driving the state of the `Rtc` forward is a run loop that looks like this.
//!
//! ```no_run
//! # use str0m::{Rtc, Output, IceConnectionState, Event, Input};
//! # use str0m::net::Receive;
//! # use std::io::ErrorKind;
//! # use std::net::UdpSocket;
//! # use std::time::Instant;
//! # let rtc = Rtc::new();
//! #
//! // Buffer for reading incoming UDP packet.s
//! let mut buf = vec![0; 2000];
//!
//! // A UdpSocket we obtained _somehow_.
//! let socket: UdpSocket = todo!();
//!
//! loop {
//!     // Poll output until we get a timeout. The timeout means we
//!     // are either awaiting UDP socket input or the timeout to happen.
//!     let timeout = match rtc.poll_output().unwrap() {
//!         // Stop polling when we get the timeout.
//!         Output::Timeout(v) => v,
//!
//!         // Transmit this data to the remote peer. Typically via
//!         // a UDP socket. The destination IP comes from the ICE
//!         // agent. It might change during the session.
//!         Output::Transmit(v) => {
//!             socket.send_to(&v.contents, v.destination).unwrap();
//!             continue;
//!         }
//!
//!         // Events are mainly incoming media data from the remote
//!         // peer, but also data channel data and statistics.
//!         Output::Event(v) => {
//!
//!             // Abort if we disconnect.
//!             if v == Event::IceConnectionStateChange(IceConnectionState::Disconnected) {
//!                 return;
//!             }
//!
//!             // TODO: handle more cases of v here.
//!
//!             continue;
//!         }
//!     };
//!
//!     // Duration until timeout.
//!     let duration = timeout - Instant::now();
//!
//!     // socket.set_read_timeout(Some(0)) is not ok
//!     if duration.is_zero() {
//!         // Drive time forwards in rtc straight away.
//!         rtc.handle_input(Input::Timeout(Instant::now())).unwrap();
//!         continue;
//!     }
//!
//!     socket.set_read_timeout(Some(duration)).unwrap();
//!
//!     // Scale up buffer to receive an entire UDP packet.
//!     buf.resize(2000, 0);
//!
//!     // Try to receive
//!     let input = match socket.recv_from(&mut buf) {
//!         Ok((n, source)) => {
//!             // UDP data received before timeout.
//!             buf.truncate(n);
//!             Input::Receive(
//!                 Instant::now(),
//!                 Receive {
//!                     source,
//!                     destination: socket.local_addr().unwrap(),
//!                     contents: buf.as_slice().try_into().unwrap(),
//!                 },
//!             )
//!         }
//!
//!         Err(e) => match e.kind() {
//!             // Expected error for set_read_timeout().
//!             // One for windows, one for the rest.
//!             ErrorKind::WouldBlock
//!                 | ErrorKind::TimedOut => Input::Timeout(Instant::now()),
//!
//!             e => {
//!                 eprintln!("Error: {:?}", e);
//!                 return; // abort
//!             }
//!         },
//!     };
//!
//!     // Input is either a Timeout or Receive of data. Both drive forward.
//!     rtc.handle_input(input).unwrap();
//! }
//! ```
//!
//! ## Sending media data
//!
//! When creating the media, we can decide which codecs to support, which
//! is then negotiated with the remote side. Each codec corresponds to a
//! "payload type" (PT). To send media data we need to figure out which PT
//! to use when sending.
//!
//! ```no_run
//! # use str0m::Rtc;
//! # use str0m::media::Mid;
//! # let rtc: Rtc = todo!();
//! #
//! // Obtain mid from Event::MediaAdded
//! let mid: Mid = todo!();
//!
//! // Get the `Media` for this `mid`
//! let media = rtc.media(mid).unwrap();
//!
//! // Get the payload type (pt) for the wanted codec.
//! let pt = media.payload_params()[0].pt();
//!
//! // Create a media writer for the payload type.
//! let writer = media.writer(pt);
//!
//! // Write the data
//! let wallclock = todo!();  // Absolute time of the data
//! let media_time = todo!(); // Media time, in RTP time
//! let data = todo!();       // Actual data
//! writer.write(wallclock, media_time, data).unwrap();
//! ```
//!
//! ## Media time, wallclock and local time
//!
//! str0m has three main concepts of time. "now", media time and wallclock.
//!
//! ### Now
//!
//! Some calls in str0m, such as `Rtc::handle_input` takes a `now` argument
//! that is a `std::time::Instant`. These calls "drive the time forward" in
//! the internal state. This is used for everything like deciding when
//! to produce various feedback reports (RTCP) to remote peers, to
//! bandwidth estimation (BWE) and statistics.
//!
//! Str0m has _no internal clock_ calls. I.e. str0m never calls
//! `Instant::now()` itself. All time is external input. That means it's
//! possible to construct test cases driving an `Rtc` instance faster
//! than realtime (see the [integration tests][intg]).
//!
//! ### Media time
//!
//! Each RTP header has a 32 bit number that str0m calls _media time_.
//! Media time is in some time base that is dependent on the codec,
//! however all codecs in str0m use 90_000Hz for video and 48_000Hz
//! for audio.
//!
//! For video the `MediaTime` type is `<timestamp>/90_000` str0m extends
//! the 32 bit number in the RTP header to 64 bit taking into account
//! "rollover". 64 bit is such a large number the user doesn't need to
//! think about rollovers.
//!
//! ### Wallclock
//!
//! With _wallclock_ str0m means the time a sample of media was produced
//! at an originating source. I.e. if we are talking into a microphone the
//! wallclock is the NTP time the sound is sampled.
//!
//! We can't know the exact wallclock for media from a remote peer since
//! not every device is synchronized with NTP. Every sender does
//! periodically produce a Sender Report (SR) that contain the peer's
//! idea of its wallclock, however this number can be very wrong compared to
//! "real" NTP time.
//!
//! Furthermore, not all remote devices will have a linear idea of
//! time passing that exactly matches the local time. A minute on the
//! remote peer might not be exactly one minute locally.
//!
//! These timestamps become important when handling simultaneous audio from
//! multiple peers.
//!
//! When writing media we need to provide str0m with an estimated wallclock.
//! The simplest strategy is to only trust local time and use arrival time
//! of the incoming UDP packet. Another simple strategy is to lock some
//! time T at the first UDP packet, and then offset each wallclock using
//! `MediaTime`, i.e. for video we could have `T + <media time>/90_000`
//!
//! A production worthy SFU probably needs an even more sophisticated
//! strategy weighing in all possible time sources to get a good estimate
//! of the remote wallclock for a packet.
//!
//! # Project status
//!
//! Str0m was originally developed by Martin Algesten of
//! [Lookback][lookback]. We use str0m for a specific use case: str0m as a
//! server SFU (as opposed to peer-2-peer). That means we are heavily
//! testing and developing the parts needed for our use case. Str0m is
//! intended to be an all-purpose WebRTC library, which means it should
//! also work for peer-2-peer (mostly thinking about the ICE agent), but
//! these areas have not received as much attention and testing.
//!
//! While performance is very good, only some attempts have been made to
//! discover and optimize bottlenecks. For instance, while str0m probably
//! never be allocation free, there might be unnecessary allocations and
//! cloning that could be improved. Another area is to make sure the
//! crypto parts use efficient algorithms and hardware acceleration as far
//! as possible.
//!
//! # Design
//!
//! Output from the `Rtc` instance can be grouped into three kinds.
//!
//! 1. Events (such as receiving media or data channel data).
//! 2. Network output. Data to be sent, typically from a UDP socket.
//! 3. Timeouts. When the instance expects a time input.
//!
//! Input to the `Rtc` instance is:
//!
//! 1. User operations (such as sending media or data channel data).
//! 2. Network input. Typically read from a UDP socket.
//! 3. Timeouts. As obtained from the output above.
//!
//! The correct use can be described like below (or seen in the examples).
//! The TODO lines is where the user would fill in their code.
//!
//! ## Overview
//!
//! ```text
//!                       +-------+
//!                       |  Rtc  |-------+----------+-------+
//!                       +-------+       |          |       |
//!                           |           |          |       |
//!                           |           |          |       |
//!            - - - -    - - - - -    - - - -    - - - - - - - -
//!           |  RTP  |--| Session |  |  ICE  |  | SCTP  | DTLS  |
//!            - - - -    - - - - -    - - - -    - - - - - - - -
//!                           |                          |
//!                           |
//!                  +--------+--------+                 |
//!                  |                 |
//!                  |                 |                 |
//!              +-------+        +---------+
//!              | Media |        | Channel |- - - - - - +
//!              +-------+        +---------+
//! ```
//!
//! Sans I/O is a pattern where we turn both network input/output as well
//! as time passing into external input to the API. This means str0m has
//! no internal threads, just an enormous state machine that is driven
//! forward by different kinds of input.
//!
//! ## Sample or RTP level?
//!
//! All codecs such as h264, vp8, vp9 and opus outputs what we call
//! "Samples". A sample has a very specific meaning for audio, but this
//! project uses it in a broader sense, where a sample is either a video
//! or audio time stamped chunk of encoded data that typically represents
//! a chunk of audio, or _one single frame for video_.
//!
//! Samples are not suitable to use directly in UDP (RTP) packets - for
//! one they are too big. Samples are therefore further chunked up by
//! codec specific packetizers into RTP packets.
//!
//! Str0m's API currently operate on the "sample level". From an
//! architectural point of view, all things RTP are considered an internal
//! detail that are largely abstracted away from the user. This is
//! different from many other RTP libraries where the RTP packets
//! themselves are the the API surface towards the user (when building an
//! SFU one would often talk about "forwarding RTP packets", while with
//! str0m we would "forward samples").
//!
//! Whether this is a good idea is still an open question. It certainly
//! makes for cleaner abstractions.
//!
//! ### RTP mode
//!
//! str0m has a lower level API which let's the user write/receive RTP
//! packets directly. Using this API requires a deeper knowledge of
//! RTP and WebRTC and is not recommended for most use cases.
//!
//! To enable RTP mode
//!
//! ```
//! # use str0m::Rtc;
//! let rtc = Rtc::builder()
//!     // Enable RTP mode for this Rtc instance.
//!     .set_rtp_mode(true)
//!     // Don't hold back audio/video packets to attempt
//!     // to reorder them. Incoming packets are released
//!     // in the order they are received.
//!     .set_reordering_size_audio(0)
//!     .set_reordering_size_video(0)
//!     .build();
//! ```
//!
//! ## NIC enumeration and TURN (and STUN)
//!
//! The [ICE RFC][ice] talks about "gathering ice candidates". This means
//! inspecting the local network interfaces and potentially binding UDP
//! sockets on each usable interface. Since str0m is Sans I/O, this part
//! is outside the scope of what str0m does. How the user figures out
//! local IP addresses, via config or via looking up local NICs is not
//! something str0m cares about.
//!
//! TURN is a way of obtaining IP addresses that can be used as fallback
//! in case direct connections fail. We consider TURN similar to
//! enumerating local network interfaces – it's a way of obtaining
//! sockets.
//!
//! All discovered candidates, be they local (NIC) or remote sockets
//! (TURN), are added to str0m and str0m will perform the task of ICE
//! agent, forming "candidate pairs" and figuring out the best connection
//! while the actual task of sending the network traffic is left to the
//! user.
//!
//! ### Input
//!
//! 1. Incoming network data
//! 2. Time going forward
//! 3. User operations such as pushing media data.
//!
//! In response to this input, the API will react with various output.
//!
//! ### Output
//!
//! 1. Outgoing network data
//! 2. Next required time to "wake up"
//! 3. Incoming events such as media data.
//!
//! ## The importance of `&mut self`
//!
//! Rust shines when we can eschew locks and heavily rely `&mut` for data
//! write access. Since str0m has no internal threads, we never have to
//! deal with shared data. Furthermore the the internals of the library is
//! organized such that we don't need multiple references to the same
//! entities.
//!
//! This means all input to the lib can be modelled as
//! `handle_something(&mut self, something)`.
//!
//! ## Not a standard WebRTC API
//!
//! The library deliberately steps away from the "standard" WebRTC API as
//! seen in JavaScript and/or [webrtc-rs][webrtc-rs] (or [Pion][pion] in Go).
//! There are few reasons for this.
//!
//! First, in the standard API, events are callbacks, which are not a
//! great fit for Rust, since callbacks require some kind of reference
//! (ownership?) over the entity the callback is being dispatched
//! upon. I.e. if in Rust we want to `pc.addEventListener(x)`, `x` needs
//! to be wholly owned by `pc`, or have some shared reference (like
//! `Arc`). Shared references means shared data, and to get mutable shared
//! data, we will need some kind of lock. i.e. `Arc<Mutex<EventListener>>`
//! or similar.
//!
//! As an alternative we could turn all events into `mpsc` channels, but
//! listening to multiple channels is awkward without async.
//!
//! Second, in the standard API, entities like `RTCPeerConnection` and
//! `RTCRtpTransceiver`, are easily clonable and/or long lived
//! references. I.e. `pc.getTranscievers()` returns objects that can be
//! retained and owned by the caller. This pattern is fine for garbage
//! collected or reference counted languages, but not great with Rust.
//!
//! # Running the example
//!
//! For the browser to do WebRTC, all traffic must be under TLS. The
//! project ships with a self-signed certificate that is used for the
//! examples. The certificate is for hostname `str0m.test` since TLD .test
//! should never resolve to a real DNS name.
//!
//! 1. Edit `/etc/hosts` so `str0m.test` to loopback.
//!
//! ```text
//! 127.0.0.1    localhost str0m.test
//! ```
//!
//! 2. Start the example server `cargo run --example http-post`
//!
//! 3. In a browser, visit `https://str0m.test:3000/`. This will complain
//! about the TLS certificate, you need to accept the "risk". How to do
//! this depends on browser. In Chrome you can expand "Advanced" and
//! chose "Proceed to str0m.test (unsafe)". For Safari, you can
//! similarly chose to "Visit website" despite the warning.
//!
//! 4. Click "Cam" and/or "Mic" followed by "Rtc". And hopefully you will
//! see something like this in the log:
//!
//! ```text
//! Dec 18 11:33:06.850  INFO str0m: MediaData(MediaData { mid: Mid(0), pt: Pt(104), time: MediaTime(3099135646, 90000), len: 1464 })
//! Dec 18 11:33:06.867  INFO str0m: MediaData(MediaData { mid: Mid(0), pt: Pt(104), time: MediaTime(3099138706, 90000), len: 1093 })
//! Dec 18 11:33:06.907  INFO str0m: MediaData(MediaData { mid: Mid(0), pt: Pt(104), time: MediaTime(3099141676, 90000), len: 1202 })
//!```
//!
//! [sansio]:     https://sans-io.readthedocs.io
//! [quinn]:      https://github.com/quinn-rs/quinn
//! [pion]:       https://github.com/pion/webrtc
//! [webrtc-rs]:  https://github.com/webrtc-rs/webrtc
//! [zulip]:      https://str0m.zulipchat.com/join/hsiuva2zx47ujrwgmucjez5o/
//! [ice]:        https://www.rfc-editor.org/rfc/rfc8445
//! [lookback]:   https://www.lookback.com
//! [x-post]:     https://github.com/algesten/str0m/blob/main/examples/http-post.rs
//! [x-chat]:     https://github.com/algesten/str0m/blob/main/examples/chat.rs
//! [intg]:       https://github.com/algesten/str0m/blob/main/tests/unidirectional.rs#L12

#![forbid(unsafe_code)]
#![allow(clippy::new_without_default)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::assertions_on_constants)]
#![deny(missing_docs)]

#[macro_use]
extern crate tracing;

mod dtls;
mod ice;
mod io;
mod packet;
mod rtp;
mod sctp;
mod sdp;

pub mod format;

use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use change::Fingerprint;
use change::{DirectApi, SdpApi};
use dtls::DtlsCert;
use dtls::{Dtls, DtlsEvent};
use format::CodecConfig;
use ice::IceAgent;
use ice::IceAgentEvent;
use ice::IceCreds;
use io::DatagramRecv;
use rtp::{Extension, ExtensionMap, InstantExt, Ssrc};
use sctp::{RtcSctp, SctpEvent};

use stats::{MediaEgressStats, MediaIngressStats, PeerStats, Stats, StatsEvent};
use thiserror::Error;

pub use ice::IceConnectionState;

pub use ice::Candidate;
pub use rtp::Bitrate;

/// Network related types to get socket data in/out of [`Rtc`].
pub mod net {
    pub use crate::io::{DatagramRecv, DatagramSend, Receive, Transmit};
}

/// Various error types.
pub mod error {
    pub use crate::dtls::DtlsError;
    pub use crate::ice::IceError;
    pub use crate::io::NetError;
    pub use crate::packet::PacketError;
    pub use crate::rtp::RtpError;
    pub use crate::sctp::{ProtoError, SctpError};
    pub use crate::sdp::SdpError;
}

pub mod channel;
use channel::{Channel, ChannelData, ChannelHandler, ChannelId};

pub mod media;
use media::{Direction, KeyframeRequest, Media};
use media::{KeyframeRequestKind, MediaChanged, MediaData};
use media::{MediaAdded, MediaInner, Mid, PolledPacket, Pt, Rid};

pub mod change;

mod util;
pub(crate) use util::*;

mod session;
use session::{MediaEvent, Session};

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
    Io(#[from] std::io::Error),

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

    /// Direction does not allow sending of Media data.
    #[error("Direction does not allow sending: {0}")]
    NotSendingDirection(Direction),

    /// If MediaWriter.request_keyframe fails because we can't find an SSRC to use.
    #[error("No receiver source (rid: {0:?})")]
    NoReceiverSource(Option<Rid>),

    /// The keyframe request failed because the kind of request is not enabled
    /// in the media.
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

    /// [`SdpApi`] was not done in a correct order.
    ///
    /// For [`SdpApi`][change::SdpApi]:
    ///
    /// 1. We created an [`SdpOffer`][change::SdpOffer].
    /// 2. The remote side created an [`SdpOffer`][change::SdpOffer] at the same time.
    /// 3. We applied the remote side [`SdpApi::accept_offer()`][change::SdpOffer].
    /// 4. The we used the [`SdpPendingOffer`][change::SdpPendingOffer] created in step 1.
    #[error("Changes made out of order")]
    ChangesOutOfOrder,

    /// Some other error.
    #[error("{0}")]
    Other(String),
}

/// Instance that does WebRTC. Main struct of the entire library.
///
/// ## Usage
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
///     //       or receiving network input. Both are encapsulated
///     //       in the Input enum.
///     let input: Input = todo!();
///
///     rtc.handle_input(input).unwrap();
/// }
/// ```
pub struct Rtc {
    alive: bool,
    ice: IceAgent,
    dtls: Dtls,
    sctp: RtcSctp,
    chan: ChannelHandler,
    stats: Option<Stats>,
    session: Session,
    remote_fingerprint: Option<Fingerprint>,
    remote_addrs: Vec<SocketAddr>,
    send_addr: Option<SendAddr>,
    last_now: Instant,
    peer_bytes_rx: u64,
    peer_bytes_tx: u64,
    change_counter: usize,
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
    /// Emitted when we got ICE connection and established DTLS.
    Connected,

    /// ICE connection state changes tells us whether the [`Rtc`] instance is
    /// connected to the peer or not.
    IceConnectionStateChange(IceConnectionState),

    /// Upon adding new media to the session. The lines are emitted.
    ///
    /// Upon this event, the [`Media`] instance is available via [`Rtc::media()`].
    MediaAdded(MediaAdded),

    /// Incoming media data sent by the remote peer.
    MediaData(MediaData),

    /// Changes to the media may be emitted.
    ///
    ///. Currently only covers a change of direction.
    MediaChanged(MediaChanged),

    /// Incoming keyframe request for media that we are sending to the remote peer.
    ///
    /// The request is either PLI (Picture Loss Indication) or FIR (Full Intra Request).
    KeyframeRequest(KeyframeRequest),

    /// A data channel has opened.
    ///
    /// The string is the channel label which is set by the opening peer and can
    /// be used to identify the purpose of the channel when there are more than one.
    ///
    /// The negotiation is to set up an SCTP association via DTLS. Subsequent data
    /// channels reuse the same association.
    ///
    /// Upon this event, the [`Channel`] can be obtained via [`Rtc::channel()`].
    ///
    /// For [`SdpApi`]: The first ever data channel results in an SDP
    /// negotiation, and this events comes at the end of that.
    ChannelOpen(ChannelId, String),

    /// Incoming data channel data from the remote peer.
    ChannelData(ChannelData),

    /// A data channel has been closed.
    ChannelClose(ChannelId),

    /// Statistics event for the Rtc instance
    ///
    /// Includes both media traffic (rtp payload) as well as all traffic
    PeerStats(PeerStats),

    /// Aggregated statistics for each media (mid, rid) in the ingress direction
    MediaIngressStats(MediaIngressStats),

    /// Aggregated statistics for each media (mid, rid) in the egress direction
    MediaEgressStats(MediaEgressStats),

    /// A new estimate from the bandwidth estimation subsystem.
    EgressBitrateEstimate(Bitrate),
}

/// Input as expected by [`Rtc::handle_input()`]. Either network data or a timeout.
#[derive(Debug)]
pub enum Input<'a> {
    /// A timeout without any network input.
    Timeout(Instant),
    /// Network input.
    Receive(Instant, net::Receive<'a>),
}

/// Output produced by [`Rtc::poll_output()`]
pub enum Output {
    /// When the [`Rtc`] instance expects an [`Input::Timeout`].
    Timeout(Instant),

    /// Network data that is to be sent.
    Transmit(net::Transmit),

    /// Some event such as media data arriving from the remote peer or connection events.
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
    ///     .set_ice_lite(true)
    ///     .build();
    /// ```
    pub fn builder() -> RtcConfig {
        RtcConfig::new()
    }

    pub(crate) fn new_from_config(config: RtcConfig) -> Self {
        let session = Session::new(&config);

        let mut ice = IceAgent::with_local_credentials(config.local_ice_credentials);
        if config.ice_lite {
            ice.set_ice_lite(config.ice_lite);
        }

        Rtc {
            alive: true,
            ice,
            dtls: Dtls::new(config.dtls_cert).expect("DTLS to init without problem"),
            session,
            sctp: RtcSctp::new(),
            chan: ChannelHandler::default(),
            stats: config.stats_interval.map(Stats::new),
            remote_fingerprint: None,
            remote_addrs: vec![],
            send_addr: None,
            last_now: already_happened(),
            peer_bytes_rx: 0,
            peer_bytes_tx: 0,
            change_counter: 0,
        }
    }

    /// Tests if this instance is still working.
    ///
    /// Certain events will straight away disconnect the `Rtc` instance, such as
    /// the DTLS fingerprint from the setup not matching that of the TLS negotiation
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
    /// however advisable to add at least one local candidate before starting the instance.
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
    /// For [`SdpApi`]: Remote candidates are typically added via
    /// receiving a remote [`SdpOffer`][change::SdpOffer] or [`SdpAnswer`][change::SdpAnswer].
    ///
    /// However for the case of [Trickle Ice][1], this is the way to add remote candidates
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

    /// Checks if we are connected.
    ///
    /// This tests both if we have ICE connection and DTLS is ready.
    ///
    pub fn is_connected(&self) -> bool {
        self.ice.state().is_connected() && self.dtls.is_connected()
    }

    /// Make changes to the Rtc session via SDP.
    ///
    /// ```no_run
    /// # use str0m::Rtc;
    /// # use str0m::media::{MediaKind, Direction};
    /// # use str0m::change::SdpAnswer;
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.sdp_api();
    /// let mid_audio = changes.add_media(MediaKind::Audio, Direction::SendOnly, None, None);
    /// let mid_video = changes.add_media(MediaKind::Video, Direction::SendOnly, None, None);
    ///
    /// let (offer, pending) = changes.apply().unwrap();
    /// let json = serde_json::to_vec(&offer).unwrap();
    ///
    /// // Send json OFFER to remote peer. Receive an answer back.
    /// let answer: SdpAnswer = todo!();
    ///
    /// rtc.sdp_api().accept_answer(pending, answer).unwrap();
    /// ```
    pub fn sdp_api(&mut self) -> SdpApi {
        SdpApi::new(self)
    }

    /// Makes direct changes to the Rtc session.
    ///
    /// This is a low level API. For "normal" use via SDP, see [`Rtc::sdp_api()`].
    pub fn direct_api(&mut self) -> DirectApi {
        DirectApi::new(self)
    }

    fn init_dtls(&mut self, active: bool) -> Result<(), RtcError> {
        if self.dtls.is_inited() {
            return Ok(());
        }

        info!("DTLS setup is: {:?}", active);
        self.dtls.set_active(active);

        if active {
            self.dtls.handle_handshake()?;
        }

        Ok(())
    }

    fn init_sctp(&mut self, client: bool) {
        // If we got an m=application line, ensure we have negotiated the
        // SCTP association with the other side.
        if self.sctp.is_inited() {
            return;
        }

        self.sctp.init(client, self.last_now);
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
                    info!(
                        "ICE nominated send from: {:?} to: {:?}",
                        source, destination
                    );
                    self.send_addr = Some(SendAddr {
                        source,
                        destination,
                    });
                }
            }
        }

        let mut dtls_connected = false;

        while let Some(e) = self.dtls.poll_event() {
            match e {
                DtlsEvent::Connected => {
                    debug!("DTLS connected");
                    dtls_connected = true;
                }
                DtlsEvent::SrtpKeyingMaterial(mat) => {
                    info!("DTLS set SRTP keying material");
                    let active = self.dtls.is_active().expect("DTLS must be inited by now");
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

        if dtls_connected {
            return Ok(Output::Event(Event::Connected));
        }

        while let Some(e) = self.sctp.poll() {
            match e {
                SctpEvent::Transmit { mut packets } => {
                    if let Some(v) = packets.front() {
                        if let Err(e) = self.dtls.handle_input(v) {
                            if e.is_would_block() {
                                self.sctp.push_back_transmit(packets);
                                break;
                            } else {
                                return Err(e.into());
                            }
                        }
                        packets.pop_front();
                        break;
                    }
                }
                SctpEvent::Open { id, label } => {
                    self.chan.ensure_channel_id_for(id);
                    let id = self.chan.channel_id_by_stream_id(id).unwrap();
                    return Ok(Output::Event(Event::ChannelOpen(id, label)));
                }
                SctpEvent::Close { id } => {
                    let Some(id) = self.chan.channel_id_by_stream_id(id) else {
                        warn!("Drop ChannelClose event for id: {:?}", id);
                        continue;
                    };
                    return Ok(Output::Event(Event::ChannelClose(id)));
                }
                SctpEvent::Data { id, binary, data } => {
                    let Some(id) = self.chan.channel_id_by_stream_id(id) else {
                        warn!("Drop ChannelData event for id: {:?}", id);
                        continue;
                    };
                    let cd = ChannelData { id, binary, data };
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
                MediaEvent::EgressBitrateEstimate(b) => {
                    Output::Event(Event::EgressBitrateEstimate(b))
                }
            });
        }

        if let Some(e) = self.stats.as_mut().and_then(|s| s.poll_output()) {
            return Ok(match e {
                StatsEvent::Peer(s) => Output::Event(Event::PeerStats(s)),
                StatsEvent::MediaIngress(s) => Output::Event(Event::MediaIngressStats(s)),
                StatsEvent::MediaEgress(s) => Output::Event(Event::MediaEgressStats(s)),
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
            .soonest((self.sctp.poll_timeout(), "sctp"))
            .soonest((self.chan.poll_timeout(&self.sctp), "chan"))
            .soonest((self.stats.as_mut().and_then(|s| s.poll_timeout()), "stats"));

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
    /// is delegated to the ICE agent which recognizes the remote peer from `a=ufrag`/`a=password`
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
            Input::Timeout(now) => self.do_handle_timeout(now)?,
            Input::Receive(now, r) => {
                self.do_handle_receive(now, r)?;
                self.do_handle_timeout(now)?;
            }
        }
        Ok(())
    }

    fn do_handle_timeout(&mut self, now: Instant) -> Result<(), RtcError> {
        // We assume this first "now" is a time 0 start point for calculating ntp/unix time offsets.
        // This initializes the conversion of Instant -> NTP/Unix time.
        let _ = now.to_unix_duration();
        self.last_now = now;
        self.ice.handle_timeout(now);
        self.sctp.handle_timeout(now);
        self.chan.handle_timeout(now, &mut self.sctp);
        self.session.handle_timeout(now)?;

        if let Some(stats) = &mut self.stats {
            if stats.wants_timeout(now) {
                let mut snapshot = StatsSnapshot::new(now);
                snapshot.peer_rx = self.peer_bytes_rx;
                snapshot.peer_tx = self.peer_bytes_tx;
                self.session.visit_stats(now, &mut snapshot);
                stats.do_handle_timeout(&mut snapshot);
            }
        }

        Ok(())
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

        self.peer_bytes_rx += bytes_rx as u64;

        match r.contents {
            Stun(_) => self.ice.handle_receive(now, r),
            Dtls(_) => self.dtls.handle_receive(r)?,
            Rtp(_) | Rtcp(_) => self.session.handle_receive(now, r),
        }

        Ok(())
    }

    /// Get a [`Media`] instance for inspecting and manipulating media. Media has a 1-1
    /// relationship with "m-line" from the SDP. The `Media` instance is used for media
    /// regardless of current direction.
    ///
    /// Apart from inspecting information about the media, there are two fundamental
    /// operations. One is [`Media::writer()`] for writing outgoing media data, the other
    /// is [`Media::request_keyframe()`][crate::media::Media] to request a PLI/FIR keyframe for incoming media data.
    ///
    /// All media rows are announced via the [`Event::MediaAdded`] event. This function
    /// will return `None` for any [`Mid`] until that event has fired. This
    /// is also the case for the `mid` that comes from [`SdpApi::add_media()`].
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
    pub fn media(&mut self, mid: Mid) -> Option<Media<'_>> {
        if !self.alive {
            return None;
        }
        // Check the media exists. After this we don't check again going via Rtc::media_by_mid
        self.session.media_by_mid(mid)?;
        Some(Media::new(self, mid))
    }

    /// Obtain handle for writing to a data channel.
    ///
    /// This is first available when a [`ChannelId`] is advertised via [`Event::ChannelOpen`].
    /// The function returns `None` also for IDs from [`SdpApi::add_channel()`].
    ///
    /// Incoming channel data is via the [`Event::ChannelData`] event.
    ///
    /// ```no_run
    /// # use str0m::{Rtc, channel::ChannelId};
    /// let mut rtc = Rtc::new();
    ///
    /// let cid: ChannelId = todo!(); // obtain Mid from Event::ChannelOpen
    /// let channel = rtc.channel(cid).unwrap();
    /// // TODO write data channel data.
    /// ```
    pub fn channel(&mut self, id: ChannelId) -> Option<Channel<'_>> {
        if !self.alive {
            return None;
        }

        let sctp_stream_id = self.chan.stream_id_by_channel_id(id)?;

        if !self.sctp.is_open(sctp_stream_id) {
            return None;
        }

        Some(Channel::new(sctp_stream_id, self))
    }

    /// Configure the Bandwidth Estimate (BWE) subsystem.
    ///
    /// Only relevant if BWE was enabled in the [`RtcConfig::enable_bwe()`]
    pub fn bwe(&mut self) -> Bwe {
        Bwe(self)
    }

    fn is_correct_change_id(&self, change_id: usize) -> bool {
        self.change_counter == change_id + 1
    }

    fn next_change_id(&mut self) -> usize {
        let n = self.change_counter;
        self.change_counter += 1;
        n
    }

    fn media_inner(&self, mid: Mid) -> &MediaInner {
        self.session
            .media_by_mid(mid)
            .expect("mid to match a media")
    }

    fn media_inner_mut(&mut self, mid: Mid) -> &mut MediaInner {
        self.session
            .media_by_mid_mut(mid)
            .expect("mid to match a media")
    }
}

/// Customized config for creating an [`Rtc`] instance.
///
/// ```
/// use str0m::RtcConfig;
///
/// let rtc = RtcConfig::new()
///     .set_ice_lite(true)
///     .build();
/// ```
///
/// Configs implement [`Clone`] to help create multiple `Rtc` instances.
#[derive(Debug, Clone)]
pub struct RtcConfig {
    local_ice_credentials: IceCreds,
    dtls_cert: DtlsCert,
    ice_lite: bool,
    codec_config: CodecConfig,
    exts: ExtensionMap,
    stats_interval: Option<Duration>,
    /// Whether to use Bandwidth Estimation to discover the egress bandwidth.
    bwe_initial_bitrate: Option<Bitrate>,
    reordering_size_audio: usize,
    reordering_size_video: usize,

    rtp_mode: bool,
}

impl RtcConfig {
    /// Creates a new default config.
    pub fn new() -> Self {
        RtcConfig::default()
    }

    /// The auto generated local ice credentials.
    pub fn local_ice_credentials(&self) -> &IceCreds {
        &self.local_ice_credentials
    }

    /// The configured DtlsCert.
    ///
    /// The certificate is uniquely created per new RtcConfig.
    pub fn dtls_cert(&self) -> &DtlsCert {
        &self.dtls_cert
    }

    /// Toggle ice lite. Ice lite is a mode for WebRTC servers with public IP address.
    /// An [`Rtc`] instance in ice lite mode will not make STUN binding requests, but only
    /// answer to requests from the remote peer.
    ///
    /// See [ICE RFC][1]
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc8445#page-13
    pub fn set_ice_lite(mut self, enabled: bool) -> Self {
        self.ice_lite = enabled;
        self
    }

    /// Tells whether ice lite is enabled.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to false.
    /// assert_eq!(config.ice_lite(), false);
    /// ```
    pub fn ice_lite(&self) -> bool {
        self.ice_lite
    }

    /// Lower level access to precis configuration of codecs (payload types).
    pub fn codec_config(&mut self) -> &mut CodecConfig {
        &mut self.codec_config
    }

    /// Clear all configured codecs.
    ///
    /// ```
    /// # use str0m::RtcConfig;
    ///
    /// // For the session to use only OPUS and VP8.
    /// let mut rtc = RtcConfig::default()
    ///     .clear_codecs()
    ///     .enable_opus(true)
    ///     .enable_vp8(true)
    ///     .build();
    /// ```
    pub fn clear_codecs(mut self) -> Self {
        self.codec_config.clear();
        self
    }

    /// Enable opus audio codec.
    ///
    /// Enabled by default.
    pub fn enable_opus(mut self, enabled: bool) -> Self {
        self.codec_config.enable_opus(enabled);
        self
    }

    /// Enable VP8 video codec.
    ///
    /// Enabled by default.
    pub fn enable_vp8(mut self, enabled: bool) -> Self {
        self.codec_config.enable_vp8(enabled);
        self
    }

    /// Enable H264 video codec.
    ///
    /// Enabled by default.
    pub fn enable_h264(mut self, enabled: bool) -> Self {
        self.codec_config.enable_h264(enabled);
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
    pub fn enable_vp9(mut self, enabled: bool) -> Self {
        self.codec_config.enable_vp9(enabled);
        self
    }

    /// Configure the RTP extension mappings.
    ///
    /// The default extension map is
    ///
    /// ```
    /// # use str0m::media::rtp::{Extension, ExtensionMap};
    /// let exts = ExtensionMap::standard();
    ///
    /// assert_eq!(exts.id_of(Extension::AudioLevel), Some(1));
    /// assert_eq!(exts.id_of(Extension::AbsoluteSendTime), Some(2));
    /// assert_eq!(exts.id_of(Extension::TransportSequenceNumber), Some(3));
    /// assert_eq!(exts.id_of(Extension::RtpMid), Some(4));
    /// assert_eq!(exts.id_of(Extension::RtpStreamId), Some(10));
    /// assert_eq!(exts.id_of(Extension::RepairedRtpStreamId), Some(11));
    /// assert_eq!(exts.id_of(Extension::VideoOrientation), Some(13));
    /// ```
    pub fn extension_map(&mut self) -> &mut ExtensionMap {
        &mut self.exts
    }

    /// Clear out the standard extension mappings.
    pub fn clear_extension_map(mut self) -> Self {
        self.exts.clear();

        self
    }

    /// Set an extension mapping on session level.
    ///
    /// The media level will be capped by the extension enabled on session level.
    ///
    /// The id must be 1-14 inclusive (1-indexed).
    pub fn set_extension(mut self, id: u8, ext: Extension) -> Self {
        self.exts.set(id, ext);
        self
    }

    /// Set the interval between statistics events.
    ///
    /// None turns off the stats events.
    ///
    /// This includes [`MediaEgressStats`], [`MediaIngressStats`], [`MediaEgressStats`]
    pub fn set_stats_interval(mut self, interval: Option<Duration>) -> Self {
        self.stats_interval = interval;
        self
    }

    /// The configured statistics interval.
    ///
    /// None means statistics are disabled.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// # use std::time::Duration;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to None.
    /// assert_eq!(config.stats_interval(), None);
    /// ```
    pub fn stats_interval(&self) -> Option<Duration> {
        self.stats_interval
    }

    /// Enables estimation of available bandwidth (BWE).
    ///
    /// None disables the BWE. This is an estimation of the send bandwidth, not receive.
    ///
    /// This includes setting the initial estimate to start with.
    pub fn enable_bwe(mut self, initial_estimate: Option<Bitrate>) -> Self {
        self.bwe_initial_bitrate = initial_estimate;

        self
    }

    /// The initial bitrate as set by [`Self::enable_bwe()`].
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to None - BWE off.
    /// assert_eq!(config.bwe_initial_bitrate(), None);
    /// ```
    pub fn bwe_initial_bitrate(&self) -> Option<Bitrate> {
        self.bwe_initial_bitrate
    }

    /// Sets the number of packets held back for reordering audio packets.
    ///
    /// Str0m tries to deliver the samples in order. This number determines how many
    /// packets to "wait" before releasing media
    /// [`contiguous: false`][crate::media::MediaData::contiguous].
    ///
    /// Setting this to 0 enables a special mode where we will emit `MediaData` data out of order. This
    /// works on the assumption that we never split an audio sample over several RTP packets.
    pub fn set_reordering_size_audio(mut self, size: usize) -> Self {
        self.reordering_size_audio = size;

        self
    }

    /// Returns the setting for audio reordering size.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to 15.
    /// assert_eq!(config.reordering_size_audio(), 15);
    /// ```
    pub fn reordering_size_audio(&self) -> usize {
        self.reordering_size_audio
    }

    /// Sets the number of packets held back for reordering video packets.
    ///
    /// Str0m tries to deliver the samples in order. This number determines how many
    /// packets to "wait" before releasing media with gaps.
    ///
    /// This must be at least as big as the number of packets the biggest keyframe can be split over.
    ///
    /// WARNING: video is very different to audio. Setting this value too low will result in
    /// missing video data. The 0 (as described for audio) is not relevant for video.
    ///
    /// Default: 30
    pub fn set_reordering_size_video(mut self, size: usize) -> Self {
        self.reordering_size_video = size;

        self
    }

    /// Returns the setting for video reordering size.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to 30.
    /// assert_eq!(config.reordering_size_video(), 30);
    /// ```
    pub fn reordering_size_video(&self) -> usize {
        self.reordering_size_video
    }

    /// Make the entire Rtc be in RTP mode.
    ///
    /// This means all media, read from [`MediaData`] and written to
    /// [`Writer::write_rtp()`][crate::media::Writer::write_rtp()] are RTP packetized.
    /// It bypasses all internal packetization/depacketization inside str0m.
    ///
    /// WARNING: This is a low level API and is not str0m's primary use case.
    pub fn set_rtp_mode(mut self, enabled: bool) -> Self {
        self.rtp_mode = enabled;

        self
    }

    /// Checks if RTP mode is set.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to false.
    /// assert_eq!(config.rtp_mode(), false);
    /// ```
    pub fn rtp_mode(&self) -> bool {
        self.rtp_mode
    }

    /// Create a [`Rtc`] from the configuration.
    pub fn build(self) -> Rtc {
        Rtc::new_from_config(self)
    }
}

impl Default for RtcConfig {
    fn default() -> Self {
        Self {
            local_ice_credentials: IceCreds::new(),
            dtls_cert: DtlsCert::new(),
            ice_lite: false,
            codec_config: CodecConfig::new_with_defaults(),
            exts: ExtensionMap::standard(),
            stats_interval: None,
            bwe_initial_bitrate: None,
            reordering_size_audio: 15,
            reordering_size_video: 30,

            rtp_mode: false,
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

/// Access to the Bandwidth Estimate subsystem.
pub struct Bwe<'a>(&'a mut Rtc);

impl<'a> Bwe<'a> {
    /// Configure the current bitrate.
    ///
    /// Configure the bandwidth estimation system with the current bitrate.
    /// **Note:** This only has an effect if BWE has been enabled via [`RtcConfig::enable_bwe`].
    ///
    /// * `current_bitrate` an estimate of the current bitrate being sent. When the media is
    /// produced by encoders this value should be the sum of all the target bitrates for these
    /// encoders, when the media originates from another WebRTC client it should be the sum of the
    /// configure bitrates for all tracks being sent. This value should only account for video i.e.
    /// audio bitrates should be ignored.
    ///
    /// ## Example
    ///
    /// Say you have a video track with three ingress simulcast layers: `low` with `maxBitrate` set to 250Kbits/,
    /// `medium` with `maxBitrate` set to 750Kbits/, and `high` with `maxBitrate` 1.5Mbit/s.
    /// Staring at the lower layer, call:
    ///
    /// ```
    /// # use str0m::{Rtc, Bitrate};
    /// let mut rtc = Rtc::new();
    ///
    /// rtc.bwe().set_current_bitrate(Bitrate::kbps(250));
    /// ````
    ///
    /// When a new estimate is made available that indicates a switch to the medium layer is
    /// possible, make the switch and then update the configuration:
    ///
    /// ```
    /// # use str0m::{Rtc, Bitrate};
    /// let mut rtc = Rtc::new();
    ///
    /// rtc.bwe().set_current_bitrate(Bitrate::kbps(750));
    /// ````
    ///
    /// ## Accuracy
    ///
    /// When the original media is derived from another WebRTC implementation that support BWE it's
    /// advisable to use the value from `RTCOutboundRtpStreamStats.targetBitrate` from `getStats`
    /// rather than the `maxBitrate` values from `RTCRtpEncodingParameters`.
    pub fn set_current_bitrate(&mut self, current_bitrate: Bitrate) {
        self.0.session.set_bwe_current_bitrate(current_bitrate);
    }

    /// Configure the desired bitrate.
    ///
    /// Configure the bandwidth estimation system with the desired bitrate.
    /// **Note:** This only has an effect if BWE has been enabled via [`RtcConfig::enable_bwe`].
    ///
    /// * `desired_bitrate` The bitrate you would like to eventually send at. The BWE system will
    /// try to reach this bitrate by probing with padding packets. You should allocate your media
    /// bitrate based on the estimated the BWE system produces via
    /// [`Event::EgressBitrateEstimate`]. This rate might not be reached if the network link cannot
    /// sustain the desired bitrate.
    ///
    /// ## Example
    ///
    /// Say you have three simulcast video tracks each with a high layer configured at 1.5Mbit/s.
    /// You should then set the desired bitrate to 4.5Mbit/s(or slightly higher). If the network
    /// link can sustain 4.5Mbit/s there will eventually be an [`Event::EgressBitrateEstimate`]
    /// with this estimate.
    pub fn set_desired_bitrate(&mut self, desired_bitrate: Bitrate) {
        self.0.session.set_bwe_desired_bitrate(desired_bitrate);
    }
}

/// Log a CSV like stat to stdout.
///
/// ```ignore
/// log_stat!("MY_STAT", 1, "hello", 3);
/// ```
///
/// will result in the following being printed
///
/// ```text
/// MY_STAT 1, hello, 3, {unix_timestamp_ms}
/// ````
///
/// These logs can be easily grepped for, parsed and graphed, or otherwise analyzed.
///
/// This macro turns into a NO-OP if the `_internal_dont_use_log_stats` feature is not enabled
macro_rules! log_stat {
    ($name:expr, $($arg:expr),+) => {
        #[cfg(feature = "_internal_dont_use_log_stats")]
        {
            use std::time::SystemTime;
            use std::io::{self, Write};

            let now = SystemTime::now();
            let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
            let unix_time_ms = since_epoch.as_millis();
            let mut lock = io::stdout().lock();
            write!(lock, "{} ", $name).expect("Failed to write to stdout");

            $(
                write!(lock, "{},", $arg).expect("Failed to write to stdout");
            )+
            writeln!(lock, "{}", unix_time_ms).expect("Failed to write to stdout");
        }
    };
}
pub(crate) use log_stat;

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
