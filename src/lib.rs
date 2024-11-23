//! <image src="https://user-images.githubusercontent.com/227204/226143511-66fe5264-6ab7-47b9-9551-90ba7e155b96.svg" alt="str0m logo" ></image>
//!
//! A Sans I/O WebRTC implementation in Rust.
//!
//! This is a [Sans I/O][sansio] implementation meaning the `Rtc` instance itself is not doing any network
//! talking. Furthermore it has no internal threads or async tasks. All operations are happening from the
//! calls of the public API.
//!
//! This is deliberately not a standard `RTCPeerConnection` API since that isn't a great fit for Rust.
//! See more details in below section.
//!
//! # Join us
//!
//! We are discussing str0m things on Zulip. Join us using this [invitation link][zulip]. Or browse the
//! discussions anonymously at [str0m.zulipchat.com][zulip-anon]
//!
//! <image width="300px" src="https://user-images.githubusercontent.com/227204/209446544-f8a8d673-cb1b-4144-a0f2-42307b8d8869.gif" alt="silly clip showing video playing" ></image>
//!
//! # Usage
//!
//! The [`chat`][x-chat] example shows how to connect multiple browsers
//! together and act as an SFU (Selective Forwarding Unit). The example
//! multiplexes all traffic over one server UDP socket and uses two threads
//! (one for the web server, and one for the SFU loop).
//!
//! ## TLS
//!
//! For the browser to do WebRTC, all traffic must be under TLS. The
//! project ships with a self-signed certificate that is used for the
//! examples. The certificate is for hostname `str0m.test` since TLD .test
//! should never resolve to a real DNS name.
//!
//! ```text
//! cargo run --example chat
//! ```
//!
//! The log should prompt you to connect a browser to https://10.0.0.103:3000 – this will
//! most likely cause a security warning that you must get the browser to accept.
//!
//! The [`http-post`][x-post] example roughly illustrates how to receive
//! media data from a browser client. The example is single threaded and
//! is a bit simpler than the chat. It is a good starting point to understand the API.
//!
//! ```text
//! cargo run --example http-post
//! ```
//!
//! ### Real example
//!
//! To see how str0m is used in a real project, check out [BitWHIP][bitwhip] –
//! a CLI WebRTC Agent written in Rust.
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
//! let candidate = Candidate::host(addr, "udp").unwrap();
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
//! // Instantiate a new Rtc instance.
//! let mut rtc = Rtc::new();
//!
//! // Add some ICE candidate such as a locally bound UDP port.
//! let addr = "1.2.3.4:5000".parse().unwrap();
//! let candidate = Candidate::host(addr, "udp").unwrap();
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
//! Driving the state of the `Rtc` forward is a run loop that, regardless of sync or async,
//! looks like this.
//!
//! ```no_run
//! # use str0m::{Rtc, Output, IceConnectionState, Event, Input};
//! # use str0m::net::{Receive, Protocol};
//! # use std::io::ErrorKind;
//! # use std::net::UdpSocket;
//! # use std::time::Instant;
//! # let rtc = Rtc::new();
//! // Buffer for reading incoming UDP packets.
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
//!             // TODO: handle more cases of v here, such as incoming media data.
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
//!     // Try to receive. Because we have a timeout on the socket,
//!     // we will either receive a packet, or timeout.
//!     // This is where having an async loop shines. We can await multiple things to
//!     // happen such as outgoing media data, the timeout and incoming network traffic.
//!     // When using async there is no need to set timeout on the socket.
//!     let input = match socket.recv_from(&mut buf) {
//!         Ok((n, source)) => {
//!             // UDP data received.
//!             buf.truncate(n);
//!             Input::Receive(
//!                 Instant::now(),
//!                 Receive {
//!                     proto: Protocol::Udp,
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
//!     // Input is either a Timeout or Receive of data. Both drive the state forward.
//!     rtc.handle_input(input).unwrap();
//! }
//! ```
//!
//! ## Sending media data
//!
//! When creating the media, we can decide which codecs to support, and they
//! are negotiated with the remote side. Each codec corresponds to a
//! "payload type" (PT). To send media data we need to figure out which PT
//! to use when sending.
//!
//! ```no_run
//! # use str0m::Rtc;
//! # use str0m::media::Mid;
//! # let rtc: Rtc = todo!();
//! // Obtain mid from Event::MediaAdded
//! let mid: Mid = todo!();
//!
//! // Create a media writer for the mid.
//! let writer = rtc.writer(mid).unwrap();
//!
//! // Get the payload type (pt) for the wanted codec.
//! let pt = writer.payload_params().nth(0).unwrap().pt();
//!
//! // Write the data
//! let wallclock = todo!();   // Absolute time of the data
//! let media_time = todo!();  // Media time, in RTP time
//! let data: &[u8] = todo!(); // Actual data
//! writer.write(pt, wallclock, media_time, data).unwrap();
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
//! periodically produce a Sender Report (SR) that contains the peer's
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
//! intended to be an all-purpose WebRTC library, which means it also
//! works for peer-2-peer, though that aspect has received less testing.
//!
//! Performance is very good, there have been some work the discover and
//! optimize bottlenecks. Such efforts are of course never ending with
//! diminishing returns. While there are no glaringly obvious performance
//! bottlenecks, more work is always welcome – both algorithmically and
//! allocation/cloning in hot paths etc.
//!
//! # Design
//!
//! Output from the `Rtc` instance can be grouped into three kinds.
//!
//! 1. Events (such as receiving media or data channel data).
//! 2. Network output. Data to be sent, typically from a UDP socket.
//! 3. Timeouts. Indicates when the instance next expects a time input.
//!
//! Input to the `Rtc` instance is:
//!
//! 1. User operations (such as sending media or data channel data).
//! 2. Network input. Typically read from a UDP socket.
//! 3. Timeouts. As obtained from the output above.
//!
//! The correct use can be seen in the above [Run loop](#run-loop) or in the
//! examples.
//!
//! Sans I/O is a pattern where we turn both network input/output as well
//! as time passing into external input to the API. This means str0m has
//! no internal threads, just an enormous state machine that is driven
//! forward by different kinds of input.
//!
//! ## Sample or RTP level?
//!
//! Str0m defaults to the "sample level" which treats the RTP as an internal detail. The user
//! will thus mainly interact with:
//!
//! 1. [`Event::MediaData`][evmed] to receive full "samples" (audio frames or video frames).
//! 2. [`Writer::write`][writer] to write full samples.
//! 3. [`Writer::request_keyframe`][reqkey] to request keyframes.
//!
//! ### Sample level
//!
//! All codecs such as h264, vp8, vp9 and opus outputs what we call
//! "Samples". A sample has a very specific meaning for audio, but this
//! project uses it in a broader sense, where a sample is either a video
//! or audio time stamped chunk of encoded data that typically represents
//! a chunk of audio, or _one single frame for video_.
//!
//! Samples are not suitable to use directly in UDP (RTP) packets - for
//! one they are too big. Samples are therefore further chunked up by
//! codec specific payloaders into RTP packets.
//!
//! ### RTP mode
//!
//! Str0m also provides an RTP level API. This would be similar to many other
//! RTP libraries where the RTP packets themselves are the the API surface
//! towards the user (when building an SFU one would often talk about "forwarding
//! RTP packets", while with str0m we can also "forward samples").  Using
//! this API requires a deeper knowledge of RTP and WebRTC.
//!
//! To enable RTP mode
//!
//! ```
//! # use str0m::Rtc;
//! let rtc = Rtc::builder()
//!     // Enable RTP mode for this Rtc instance.
//!     // This disables `MediaEvent` and the `Writer::write` API.
//!     .set_rtp_mode(true)
//!     .build();
//! ```
//!
//! RTP mode gives us some new API points.
//!
//! 1. [`Event::RtpPacket`][rtppak] emitted for every incoming RTP packet. Empty packets for bandwidth
//!    estimation are silently discarded.
//! 2. [`StreamTx::write_rtp`][wrtrtp] to write outgoing RTP packets.
//! 3. [`StreamRx::request_keyframe`][reqkey2] to request keyframes from remote.
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
//! ## The importance of `&mut self`
//!
//! Rust shines when we can eschew locks and heavily rely `&mut` for data
//! write access. Since str0m has no internal threads, we never have to
//! deal with shared data. Furthermore the the internals of the library is
//! organized such that we don't need multiple references to the same
//! entities. In str0m there are no `Rc`, `Mutex`, `mpsc`, `Arc`(*),  or
//! other locks.
//!
//! This means all input to the lib can be modelled as
//! `handle_something(&mut self, something)`.
//!
//! (*) Ok. There is one `Arc` if you use Windows where we also require openssl.
//!
//! ## Not a standard WebRTC "Peer Connection" API
//!
//! The library deliberately steps away from the "standard" WebRTC API as
//! seen in JavaScript and/or [webrtc-rs][webrtc-rs] (or [Pion][pion] in Go).
//! There are few reasons for this.
//!
//! First, in the standard API, events are callbacks, which are not a
//! great fit for Rust. Callbacks require some kind of reference
//! (ownership?) over the entity the callback is being dispatched
//! upon. I.e. if in Rust we want `pc.addEventListener(x)`, `x` needs
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
//! ## Panics, Errors and unwraps
//!
//! Str0m adheres to [fail-fast][ff]. That means rather than brushing state
//! bugs under the carpet, it panics. We make a distinction between errors and
//! bugs.
//!
//! * Errors are as a result of incorrect or impossible to understand user input.
//! * Bugs are broken internal invariants (assumptions).
//!
//! If you scan the str0m code you find a few `unwrap()` (or `expect()`). These
//! will (should) always be accompanied by a code comment that explains why the
//! unwrap is okay. This is an internal invariant, a state assumption that
//! str0m is responsible for maintaining.
//!
//! We do not believe it's correct to change every `unwrap()`/`expect()` into
//! `unwrap_or_else()`, `if let Some(x) = x { ... }` etc, because doing so
//! brushes an actual problem (an incorrect assumption) under the carpet. Trying
//! to hobble along with an incorrect state would at best result in broken
//! behavior, at worst a security risk!
//!
//! Panics are our friends: *panic means bug*
//!
//! And also: str0m should *never* panic on any user input. If you encounter a panic,
//! please report it!
//!
//! ### Catching panics
//!
//! Panics should be incredibly rare, or we have a serious problem as a project. For an SFU,
//! it might not be ideal if str0m encounters a bug and brings the entire server down with it.
//!
//! For those who want an extra level of safety, we recommend looking at [`catch_unwind`][catch]
//! to safely discard a faulty `Rtc` instance. Since `Rtc` has no internal threads, locks or async
//! tasks, discarding the instance never risk poisoning locks or other issues that can happen
//! when catching a panic.
//!
//! ## FAQ
//!
//! ### Features
//!
//! Below is a brief comparison of features between libWebRTC and str0m to help you determine
//! if str0m is suitable for your project.
//!
//! | Feature                  | str0m              | libWebRTC          |
//! | ------------------------ | ------------------ | ------------------ |
//! | Peer Connection API      | :x:                | :white_check_mark: |
//! | SDP                      | :white_check_mark: | :white_check_mark: |
//! | ICE                      | :white_check_mark: | :white_check_mark: |
//! | Data Channels            | :white_check_mark: | :white_check_mark: |
//! | Send/Recv Reports        | :white_check_mark: | :white_check_mark: |
//! | Transport Wide CC        | :white_check_mark: | :white_check_mark: |
//! | Bandwidth Estimation     | :white_check_mark: | :white_check_mark: |
//! | Simulcast                | :white_check_mark: | :white_check_mark: |
//! | NACK                     | :white_check_mark: | :white_check_mark: |
//! | Packetize                | :white_check_mark: | :white_check_mark: |
//! | Fixed Depacketize Buffer | :white_check_mark: | :white_check_mark: |
//! | Adaptive Jitter Buffer   | :x:                | :white_check_mark: |
//! | Video/audio capture      | :x:                | :white_check_mark: |
//! | Video/audio encode       | :x:                | :white_check_mark: |
//! | Video/audio decode       | :x:                | :white_check_mark: |
//! | Audio render             | :x:                | :white_check_mark: |
//! | Turn                     | :x:                | :white_check_mark: |
//! | Network interface enum   | :x:                | :white_check_mark: |
//!
//! ### Platform Support
//!
//! Platforms str0m is compiled and tested on:
//!
//! | Platform                   | Compiled          | Tested            |
//! | -------------------------- | ----------------- | ----------------- |
//! | `x86_64-pc-windows-msvc`   | :white_check_mark:| :white_check_mark:|
//! | `x86_64-unknown-linux-gnu` | :white_check_mark:| :white_check_mark:|
//! | `x86_64-apple-darwin`      | :white_check_mark:| :white_check_mark:|
//!
//! If your platform isn't listed but is supported by Rust, we'd love for you to give str0m a try and
//! share your experience. We greatly appreciate your feedback!
//!
//! ### Does str0m support IPv4, IPv6, UDP and TCP?
//!
//! Certainly! str0m fully support IPv4, IPv6, UDP and TCP protocols.
//!
//! ### Can I utilize str0m with any Rust async runtime?
//!
//! Absolutely! str0m is fully sync, ensuring that it integrates seamlessly with any Rust async
//! runtime you opt for.
//!
//! ### Can I create a client with str0m?
//!
//! Of course! You have the freedom to create a client with str0m. However, please note that some
//! common client features like media encoding, decoding, and capture are not included in str0m. But
//! don't let that stop you from building amazing applications!
//!
//! ### Can I use str0m in a media server?
//!
//! Yes! str0m excels as a server component with support for both RTP API and Sample API. You can
//! easily build that recording server or SFU you dreamt of in Rust!
//!
//! ### Can I deploy the chat example into production?
//!
//! While the chat example showcases how to use str0m's API, it's not intended for production use or
//! heavy load. Writing a full-featured SFU or MCU (Multipoint Control Unit) is a significant
//! undertaking, involving various design decisions based on production requirements.
//!
//! ### Discovered a bug? Here's how to share it with us
//!
//! We'd love to hear about it! Please submit an issue and consider joining our Zulip community
//! to discuss further. For a seamless reporting experience, refer to this exemplary
//! bug report: <https://github.com/algesten/str0m/issues/382>. We appreciate your contribution
//! to making str0m better!
//!
//! ### I am allergic to SDP can you help me?
//!
//! Yes use the direct API!
//!
//! [sansio]:     https://sans-io.readthedocs.io
//! [quinn]:      https://github.com/quinn-rs/quinn
//! [pion]:       https://github.com/pion/webrtc
//! [webrtc-rs]:  https://github.com/webrtc-rs/webrtc
//! [zulip]:      https://str0m.zulipchat.com/join/hsiuva2zx47ujrwgmucjez5o/
//! [zulip-anon]: https://str0m.zulipchat.com
//! [ice]:        https://www.rfc-editor.org/rfc/rfc8445
//! [lookback]:   https://www.lookback.com
//! [x-post]:     https://github.com/algesten/str0m/blob/main/examples/http-post.rs
//! [x-chat]:     https://github.com/algesten/str0m/blob/main/examples/chat.rs
//! [intg]:       https://github.com/algesten/str0m/blob/main/tests/unidirectional.rs#L12
//! [ff]:         https://en.wikipedia.org/wiki/Fail-fast
//! [catch]:      https://doc.rust-lang.org/std/panic/fn.catch_unwind.html
//! [evmed]:      https://docs.rs/str0m/*/str0m/enum.Event.html#variant.MediaData
//! [writer]:     https://docs.rs/str0m/*/str0m/media/struct.Writer.html#method.write
//! [reqkey]:     https://docs.rs/str0m/*/str0m/media/struct.Writer.html#method.request_keyframe
//! [rtppak]:     https://docs.rs/str0m/*/str0m/enum.Event.html#variant.RtpPacket
//! [wrtrtp]:     https://docs.rs/str0m/*/str0m/rtp/struct.StreamTx.html#method.write_rtp
//! [reqkey2]:    https://docs.rs/str0m/*/str0m/rtp/struct.StreamRx.html#method.request_keyframe
//! [bitwhip]:    https://github.com/bitwhip/bitwhip

#![forbid(unsafe_code)]
#![allow(clippy::new_without_default)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::get_first)]
#![deny(missing_docs)]

#[macro_use]
extern crate tracing;

use bwe::{Bwe, BweKind};
use change::{DirectApi, SdpApi};
use rtp::RawPacket;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use streams::RtpPacket;
use streams::StreamPaused;
use thiserror::Error;
use util::InstantExt;

mod crypto;
use crypto::Fingerprint;

mod dtls;
use dtls::DtlsCert;
use dtls::{Dtls, DtlsEvent};

#[path = "ice/mod.rs"]
mod ice_;
use ice_::IceAgent;
use ice_::IceAgentEvent;
pub use ice_::{Candidate, CandidateKind, IceConnectionState, IceCreds};

/// Low level ICE access.
// The ICE API is not necessary to interact with directly for "regular"
// use of str0m. This is exported for other libraries that want to
// reuse str0m's ICE implementation. In the future we might turn this
// into a separate crate.
#[doc(hidden)]
pub mod ice {
    pub use crate::ice_::IceCreds;
    pub use crate::ice_::{IceAgent, IceAgentEvent};
    pub use crate::io::{StunMessage, StunPacket};
}

mod io;
use io::DatagramRecvInner;

mod packet;

#[path = "rtp/mod.rs"]
mod rtp_;
use rtp_::{Bitrate, DataSize};
use rtp_::{Extension, ExtensionMap};

/// Low level RTP access.
pub mod rtp {
    /// Feedback for RTP.
    pub mod rtcp {
        pub use crate::rtp_::{Descriptions, ExtendedReport, Fir, Goodbye, Nack, Pli};
        pub use crate::rtp_::{Dlrr, NackEntry, ReceptionReport, ReportBlock};
        pub use crate::rtp_::{FirEntry, ReceiverReport, SenderInfo, SenderReport, Twcc};
        pub use crate::rtp_::{ReportList, Rrtr, Rtcp, Sdes, SdesType};
    }
    use self::rtcp::Rtcp;

    /// Video Layers Allocation RTP Header Extension
    pub mod vla;
    pub use crate::rtp_::{Extension, ExtensionMap, ExtensionSerializer};
    pub use crate::rtp_::{ExtensionValues, UserExtensionValues};

    pub use crate::rtp_::{RtpHeader, SeqNo, Ssrc, VideoOrientation};
    pub use crate::streams::{RtpPacket, StreamPaused, StreamRx, StreamTx};

    /// Debug output of the unencrypted RTP and RTCP packets.
    ///
    /// Enable using [`RtcConfig::enable_raw_packets()`][crate::RtcConfig::enable_raw_packets].
    /// This clones data, and is therefore expensive.
    /// Should not be enabled outside of tests and troubleshooting.
    #[derive(Debug)]
    pub enum RawPacket {
        /// Sent RTCP.
        RtcpTx(Rtcp),
        /// Incoming RTCP.
        RtcpRx(Rtcp),
        /// Sent RTP.
        RtpTx(RtpHeader, Vec<u8>),
        /// Incoming RTP.
        RtpRx(RtpHeader, Vec<u8>),
    }
}

pub mod bwe;

mod sctp;
use sctp::{RtcSctp, SctpEvent};

mod sdp;

pub mod format;
use format::CodecConfig;

pub mod channel;
use channel::{Channel, ChannelData, ChannelHandler, ChannelId};

pub mod media;
use media::{Direction, Media, Mid, Pt, Rid, Writer};
use media::{KeyframeRequest, KeyframeRequestKind};
use media::{MediaAdded, MediaChanged, MediaData};

pub mod change;

mod util;
use util::{already_happened, not_happening, Soonest};

mod session;
use session::Session;

pub mod stats;
use stats::{MediaEgressStats, MediaIngressStats, PeerStats, Stats, StatsEvent, StatsSnapshot};

mod streams;

/// Network related types to get socket data in/out of [`Rtc`].
pub mod net {
    pub use crate::io::{DatagramRecv, DatagramSend, Protocol, Receive, Transmit};
}

/// Various error types.
pub mod error {
    pub use crate::dtls::DtlsError;
    pub use crate::ice_::IceError;
    pub use crate::io::NetError;
    pub use crate::packet::PacketError;
    pub use crate::rtp_::RtpError;
    pub use crate::sctp::{ProtoError, SctpError};
    pub use crate::sdp::SdpError;
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

    /// The Rid attempted to write is not known.
    #[error("RID is unknown {0}")]
    UnknownRid(Rid),

    /// If MediaWriter.write fails because we can't find an SSRC to use.
    #[error("No sender source")]
    NoSenderSource,

    /// Using `write_rtp` for a stream with RTX without providing a rtx_pt.
    #[error("When outgoing stream has RTX, write_rtp must be called with rtp_pt set")]
    ResendRequiresRtxPt,

    /// Direction does not allow sending of Media data.
    #[error("Direction does not allow sending: {0}")]
    NotSendingDirection(Direction),

    /// Direction does not allow receiving media data.
    #[error("Direction does not allow receiving")]
    NotReceivingDirection,

    /// If MediaWriter.request_keyframe fails because we can't find an SSRC to use.
    #[error("No receiver source (rid: {0:?})")]
    // TODO: remove rid here.
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
    /// For [`SdpApi`]:
    ///
    /// 1. We created an [`SdpOffer`][change::SdpOffer].
    /// 2. The remote side created an [`SdpOffer`][change::SdpOffer] at the same time.
    /// 3. We applied the remote side [`SdpApi::accept_offer()`][change::SdpOffer].
    /// 4. The we used the [`SdpPendingOffer`][change::SdpPendingOffer] created in step 1.
    #[error("Changes made out of order")]
    ChangesOutOfOrder,

    /// The [`Writer`] was used twice without doing `Rtc::poll_output` in between. This
    /// is an incorrect usage pattern of the str0m API.
    #[error("Consecutive calls to write() without poll_output() in between")]
    WriteWithoutPoll,
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
    need_init_time: bool,
    last_now: Instant,
    peer_bytes_rx: u64,
    peer_bytes_tx: u64,
    change_counter: usize,
    last_timeout_reason: Reason,
}

struct SendAddr {
    proto: net::Protocol,
    source: SocketAddr,
    destination: SocketAddr,
}

/// Events produced by [`Rtc::poll_output()`].
#[derive(Debug)]
#[non_exhaustive]
#[rustfmt::skip]
pub enum Event {
    // =================== ICE related events ===================

    /// Emitted when we got ICE connection and established DTLS.
    Connected,

    /// ICE connection state changes tells us whether the [`Rtc`] instance is
    /// connected to the peer or not.
    IceConnectionStateChange(IceConnectionState),

    // =================== Media related events ==================

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

    // =================== Data channel related events ===================

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

    // =================== Statistics and BWE related events ===================

    /// Statistics event for the Rtc instance
    ///
    /// Includes both media traffic (rtp payload) as well as all traffic
    PeerStats(PeerStats),

    /// Aggregated statistics for each media (mid, rid) in the ingress direction
    MediaIngressStats(MediaIngressStats),

    /// Aggregated statistics for each media (mid, rid) in the egress direction
    MediaEgressStats(MediaEgressStats),

    /// A new estimate from the bandwidth estimation subsystem.
    EgressBitrateEstimate(BweKind),

    // =================== RTP related events ===================

    /// Incoming keyframe request for media that we are sending to the remote peer.
    ///
    /// The request is either PLI (Picture Loss Indication) or FIR (Full Intra Request).
    KeyframeRequest(KeyframeRequest),

    /// Whether an incoming encoded stream is paused.
    ///
    /// This means the stream has not received any data for some time (default 1.5 seconds).
    StreamPaused(StreamPaused),

    /// Incoming RTP data.
    RtpPacket(RtpPacket),

    /// Debug output of incoming and outgoing RTCP/RTP packets.
    ///
    /// Enable using [`RtcConfig::enable_raw_packets()`].
    /// This clones data, and is therefore expensive.
    /// Should not be enabled outside of tests and troubleshooting.
    RawPacket(Box<RawPacket>),
}

impl Event {
    /// Reference to the [`RawPacket`] if this is indeed an `Event::RawPacket`.
    pub fn as_raw_packet(&self) -> Option<&RawPacket> {
        if let Self::RawPacket(boxed) = &self {
            Some(&**boxed)
        } else {
            None
        }
    }
}

/// Input as expected by [`Rtc::handle_input()`]. Either network data or a timeout.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // We purposely don't want to allocate.
pub enum Input<'a> {
    /// A timeout without any network input.
    Timeout(Instant),
    /// Network input.
    Receive(Instant, net::Receive<'a>),
}

/// Output produced by [`Rtc::poll_output()`]
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Output {
    /// When the [`Rtc`] instance expects an [`Input::Timeout`].
    Timeout(Instant),

    /// Network data that is to be sent.
    Transmit(net::Transmit),

    /// Some event such as media data arriving from the remote peer or connection events.
    Event(Event),
}

/// The reason for the next [`Output::Timeout`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// No timeout scheduled.
    ///
    /// The timeout value is in the distant future.
    NotHappening,

    /// The DTLS subsystem.
    ///
    /// Only relevant during handshaking.
    DTLS,

    /// The ICE agent.
    ///
    /// Includes checking candidate pairs and various cleanups.
    Ice,

    /// The SCTP subsystem.
    ///
    /// Things like handling retransmissions and keep-alive checks.
    Sctp,

    /// Data channels.
    ///
    /// Scheduled when we need to open allocations using SCTP.
    Channel,

    /// Stats gathering (if enabled).
    ///
    /// Periodic gathering of statistics.
    Stats,

    /// Regular RTP feedback.
    ///
    /// Receiver reports (RR) and sender reports (SR).
    Feedback,

    /// Sending of RTP NACK.
    ///
    /// When missing packets are discovered, a NACK is scheduled.
    Nack,

    /// Reporting of TWCC (if enabled).
    ///
    /// All incoming RTP packets are reported using TWCC. Enabled via SDP if both
    /// sides support it.
    Twcc,

    /// RTP streams not receiving data goes into a paused state.
    ///
    /// Whenever an RTP receive stream receives data, a new timeout is scheduled.
    PauseCheck,

    /// Preprocessing of RTP packets to be sent.
    ///
    /// Housekeeping task in RTP send streams.
    SendStream,

    /// Packetizing of media into RTP data (if used).
    ///
    /// Written media data needs packetizing. This is not used in RTP mode.
    Packetize,

    /// Paced sending of RTP packets (if BWE is enabled).
    ///
    /// The pacer ensures bigger RTP chunks, like keyframes, are not sent as a burst,
    /// but sent smoothly.
    Pacing,

    /// Bandwidth estimation update (if enabled).
    ///
    /// Calculations regarding sender bandwidth using incoming TWCC.
    Bwe,
}

impl Default for Reason {
    fn default() -> Self {
        Self::NotHappening
    }
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

        let local_creds = config.local_ice_credentials.unwrap_or_else(IceCreds::new);
        let mut ice = IceAgent::with_local_credentials(local_creds);
        if config.ice_lite {
            ice.set_ice_lite(config.ice_lite);
        }

        let dtls_cert = if let Some(c) = config.dtls_cert {
            c
        } else {
            #[cfg(feature = "openssl")]
            {
                DtlsCert::new_openssl()
            }
            #[cfg(feature = "wincrypto")]
            {
                DtlsCert::new_wincrypto()
            }
            #[cfg(not(any(feature = "openssl", feature = "wincrypto")))]
            {
                panic!("No DTLS implementation. Enable openssl feature");
            }
        };

        Rtc {
            alive: true,
            ice,
            dtls: Dtls::new(dtls_cert).expect("DTLS to init without problem"),
            session,
            sctp: RtcSctp::new(),
            chan: ChannelHandler::default(),
            stats: config.stats_interval.map(Stats::new),
            remote_fingerprint: None,
            remote_addrs: vec![],
            send_addr: None,
            need_init_time: true,
            last_now: already_happened(),
            peer_bytes_rx: 0,
            peer_bytes_tx: 0,
            change_counter: 0,
            last_timeout_reason: Reason::NotHappening,
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
    /// let c = Candidate::host(a, "udp").unwrap();
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
    /// let c = Candidate::host(a, "udp").unwrap();
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

    /// Send outgoing media data (samples) or request keyframes.
    ///
    /// Returns `None` if the direction isn't sending (`sendrecv` or `sendonly`).
    ///
    /// ```no_run
    /// # use str0m::Rtc;
    /// # use str0m::media::{MediaData, Mid};
    /// # use str0m::format::PayloadParams;
    /// let mut rtc = Rtc::new();
    ///
    /// // add candidates, do SDP negotiation
    /// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
    ///
    /// // Writer for this mid.
    /// let writer = rtc.writer(mid).unwrap();
    ///
    /// // Get incoming media data from another peer
    /// let data: MediaData = todo!();
    ///
    /// // Match incoming PT to an outgoing PT.
    /// let pt = writer.match_params(data.params).unwrap();
    ///
    /// writer.write(pt, data.network_time, data.time, data.data).unwrap();
    /// ```
    ///
    /// This is a sample level API: For RTP level see [`DirectApi::stream_tx()`] and [`DirectApi::stream_rx()`].
    ///
    pub fn writer(&mut self, mid: Mid) -> Option<Writer> {
        if self.session.rtp_mode {
            panic!("In rtp_mode use direct_api().stream_tx().write_rtp()");
        }

        self.session.media_by_mid_mut(mid)?;

        Some(Writer::new(&mut self.session, mid))
    }

    /// Currently configured media.
    ///
    /// Read only access. Changes are made via [`Rtc::sdp_api()`] or [`Rtc::direct_api()`].
    pub fn media(&self, mid: Mid) -> Option<&Media> {
        self.session.media_by_mid(mid)
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
                Event::ChannelData(_) | Event::MediaData(_) | Event::RtpPacket(_) => {
                    trace!("{:?}", e)
                }
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
            self.last_timeout_reason = Reason::NotHappening;
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
                IceAgentEvent::DiscoveredRecv { proto, source } => {
                    info!("ICE remote address: {:?}/{:?}", source, proto);
                    self.remote_addrs.push(source);
                    while self.remote_addrs.len() > 20 {
                        self.remote_addrs.remove(0);
                    }
                }
                IceAgentEvent::NominatedSend {
                    proto,
                    source,
                    destination,
                } => {
                    info!(
                        "ICE nominated send from: {:?} to: {:?} with protocol {:?}",
                        source, destination, proto,
                    );
                    self.send_addr = Some(SendAddr {
                        proto,
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
                DtlsEvent::SrtpKeyingMaterial(mat, srtp_profile) => {
                    info!(
                        "DTLS set SRTP keying material and profile: {}",
                        srtp_profile
                    );
                    let active = self.dtls.is_active().expect("DTLS must be inited by now");
                    self.session.set_keying_material(mat, srtp_profile, active);
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
                        // If there are still packets, they are sent on next
                        // poll_output()
                        if !packets.is_empty() {
                            self.sctp.push_back_transmit(packets);
                        }
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
                    self.chan.remove_channel(id);
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

        if let Some(ev) = self.session.poll_event() {
            return Ok(Output::Event(ev));
        }

        // Some polling needs to bubble up errors.
        if let Some(ev) = self.session.poll_event_fallible()? {
            return Ok(Output::Event(ev));
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
                    proto: send.proto,
                    source: send.source,
                    destination: send.destination,
                    contents,
                };
                return Ok(Output::Transmit(t));
            }
        }

        let stats = self.stats.as_mut();

        let time_and_reason = (None, Reason::NotHappening)
            .soonest((self.dtls.poll_timeout(self.last_now), Reason::DTLS))
            .soonest((self.ice.poll_timeout(), Reason::Ice))
            .soonest(self.session.poll_timeout())
            .soonest((self.sctp.poll_timeout(), Reason::Sctp))
            .soonest((self.chan.poll_timeout(&self.sctp), Reason::Channel))
            .soonest((stats.and_then(|s| s.poll_timeout()), Reason::Stats));

        // trace!("poll_output timeout reason: {}", time_and_reason.1);

        let time = time_and_reason.0.unwrap_or_else(not_happening);
        let reason = time_and_reason.1;

        // We want to guarantee time doesn't go backwards.
        let next = if time < self.last_now {
            self.last_now
        } else {
            time
        };

        self.last_timeout_reason = reason;

        Ok(Output::Timeout(next))
    }

    /// The reason for the last [`Output::Timeout`]
    ///
    /// This is updated when calling [`Rtc::poll_output()`] and the next output
    /// is a timeout.
    ///
    /// ```
    /// # use str0m::{Rtc, Input, Output, Reason};
    /// let mut rtc = Rtc::new();
    ///
    /// let output = rtc.poll_output().unwrap();
    ///
    /// // Reason updates every time we get an Output::Timeout
    /// assert!(matches!(output, Output::Timeout(_)));
    ///
    /// // If there are no timeouts scheduled, we get NotHappening. The timeout
    /// // value itself will be in the distant future.
    /// assert_eq!(rtc.last_timeout_reason(), Reason::DTLS);
    /// ```
    pub fn last_timeout_reason(&self) -> Reason {
        self.last_timeout_reason
    }

    /// Check if this `Rtc` instance accepts the given input. This is used for demultiplexing
    /// several `Rtc` instances over the same UDP server socket.
    ///
    /// [`Input::Timeout`] is always accepted. [`Input::Receive`] is tested against the nominated
    /// ICE candidate. If that doesn't match and the incoming data is a STUN packet, the accept call
    /// is delegated to the ICE agent which recognizes the remote peer from `a=ufrag`/`a=password`
    /// credentials negotiated in the SDP. If that also doesn't match, all remote ICE candidates are
    /// checked for a match.
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

        // Fast path: DTLS, RTP, and RTCP traffic coming in from the same socket address
        // we've nominated for sending via the ICE agent. This is the typical case
        if let Some(send_addr) = &self.send_addr {
            if r.source == send_addr.destination {
                return true;
            }
        }

        // STUN can use the ufrag/password to identify that a message belongs
        // to this Rtc instance.
        if let DatagramRecvInner::Stun(v) = &r.contents.inner {
            return self.ice.accepts_message(v);
        }

        // Slow path: Occasionally, traffic comes in on a socket address corresponding
        // to a successful candidate pair other than the one we've currently nominated.
        // This typically happens at the beginning of the connection
        if self.ice.has_viable_remote_candidate(r.source) {
            return true;
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

    fn init_time(&mut self, now: Instant) {
        // The operation is somewhat expensive, hence we only do it once.
        if !self.need_init_time {
            return;
        }

        // We assume this first "now" is a time 0 start point for calculating ntp/unix time offsets.
        // This initializes the conversion of Instant -> NTP/Unix time.
        let _ = now.to_unix_duration();

        self.need_init_time = false;
    }

    fn do_handle_timeout(&mut self, now: Instant) -> Result<(), RtcError> {
        self.init_time(now);

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
        self.init_time(now);

        trace!("IN {:?}", r);
        self.last_now = now;
        use DatagramRecvInner::*;

        let bytes_rx = match r.contents.inner {
            // TODO: stun is already parsed (depacketized) here
            Stun(_) => 0,
            Dtls(v) | Rtp(v) | Rtcp(v) => v.len(),
        };

        self.peer_bytes_rx += bytes_rx as u64;

        match r.contents.inner {
            Stun(stun) => {
                let packet = io::StunPacket {
                    proto: r.proto,
                    source: r.source,
                    destination: r.destination,
                    message: stun,
                };
                self.ice.handle_packet(now, packet);
            }
            Dtls(dtls) => self.dtls.handle_receive(dtls)?,
            Rtp(rtp) => self.session.handle_rtp_receive(now, rtp),
            Rtcp(rtcp) => self.session.handle_rtcp_receive(now, rtcp),
        }

        Ok(())
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
    /// let cid: ChannelId = todo!(); // obtain channel id from Event::ChannelOpen
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

    /// The codec configs for sending/receiving data.
    ///
    /// The configurations can be set with [`RtcConfig`] before setting up the session, and they
    /// might be further updated by SDP negotiation.
    pub fn codec_config(&self) -> &CodecConfig {
        &self.session.codec_config
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
    local_ice_credentials: Option<IceCreds>,
    dtls_cert: Option<DtlsCert>,
    fingerprint_verification: bool,
    ice_lite: bool,
    codec_config: CodecConfig,
    exts: ExtensionMap,
    stats_interval: Option<Duration>,
    /// Whether to use Bandwidth Estimation to discover the egress bandwidth.
    bwe_config: Option<BweConfig>,
    reordering_size_audio: usize,
    reordering_size_video: usize,
    send_buffer_audio: usize,
    send_buffer_video: usize,
    rtp_mode: bool,
    enable_raw_packets: bool,
}

#[derive(Debug, Clone)]
struct BweConfig {
    initial_bitrate: Bitrate,
    enable_loss_controller: bool,
}

impl RtcConfig {
    /// Creates a new default config.
    pub fn new() -> Self {
        RtcConfig::default()
    }

    /// Get the local ICE credentials, if set.
    ///
    /// If not specified, local credentials will be randomly generated when
    /// building the [`Rtc`] instance.
    pub fn local_ice_credentials(&self) -> &Option<IceCreds> {
        &self.local_ice_credentials
    }

    /// Explicitly sets local ICE credentials.
    pub fn set_local_ice_credentials(mut self, local_ice_credentials: IceCreds) -> Self {
        self.local_ice_credentials = Some(local_ice_credentials);
        self
    }

    /// Get the configured DTLS certificate, if set.
    ///
    /// Returns [`None`] if no DTLS certificate is set. In such cases,
    /// the certificate will be created on build and you can use the
    /// direct API on an [`Rtc`] instance to obtain the local
    /// DTLS fingerprint.
    ///
    /// ```
    /// # use str0m::RtcConfig;
    /// let fingerprint = RtcConfig::default()
    ///     .build()
    ///     .direct_api()
    ///     .local_dtls_fingerprint();
    /// ```
    pub fn dtls_cert(&self) -> Option<&DtlsCert> {
        self.dtls_cert.as_ref()
    }

    /// Set the DTLS certificate for secure communication.
    ///
    /// Generating a certificate can be a time-consuming process.
    /// Use this API to reuse a previously created [`DtlsCert`] if available.
    ///
    #[cfg_attr(
        feature = "openssl",
        doc = r##"
    /// ```
    /// # use str0m::RtcConfig;
    /// # use str0m::change::DtlsCert;
    /// let dtls_cert = DtlsCert::new_openssl();
    ///
    /// let rtc_config = RtcConfig::default()
    ///     .set_dtls_cert(dtls_cert);
    /// ```
    "##
    )]
    pub fn set_dtls_cert(mut self, dtls_cert: DtlsCert) -> Self {
        self.dtls_cert = Some(dtls_cert);
        self
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

    /// Get fingerprint verification mode.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to true.
    /// assert!(config.fingerprint_verification());
    /// ```
    pub fn fingerprint_verification(&self) -> bool {
        self.fingerprint_verification
    }

    /// Toggle certificate fingerprint verification.
    ///
    /// By default the certificate fingerprint is verified.
    pub fn set_fingerprint_verification(mut self, enabled: bool) -> Self {
        self.fingerprint_verification = enabled;
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

    /// Lower level access to precise configuration of codecs (payload types).
    pub fn codec_config(&mut self) -> &mut CodecConfig {
        &mut self.codec_config
    }

    /// Clear all configured codecs.
    ///
    /// ```
    /// # use str0m::RtcConfig;
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
    /// # use str0m::rtp::{Extension, ExtensionMap};
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

    /// Set the extension map replacing the existing.
    pub fn set_extension_map(mut self, exts: ExtensionMap) -> Self {
        self.exts = exts;
        self
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
        match initial_estimate {
            Some(b) => {
                let conf = self.bwe_config.get_or_insert(BweConfig::new(b));
                conf.initial_bitrate = b;
            }
            None => {
                self.bwe_config = None;
            }
        }

        self
    }

    /// Enable the experimental loss based BWE subsystem.
    /// Defaults to disabled for now, will be enabled by default in the future.
    pub fn enable_experimental_loss_based_bwe(mut self, enabled: bool) -> Self {
        if let Some(c) = &mut self.bwe_config {
            c.enable_loss_controller = enabled;
        }

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
        self.bwe_config.as_ref().map(|c| c.initial_bitrate)
    }

    /// Sets the number of packets held back for reordering audio packets.
    ///
    /// Str0m tries to deliver the samples in order. This number determines how many
    /// packets to "wait" before releasing media
    /// [`contiguous: false`][crate::media::MediaData::contiguous].
    ///
    /// This setting is ignored in [RTP mode][`RtcConfig::set_rtp_mode()`] where RTP
    /// packets can arrive out of order.
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
    ///
    /// This setting is ignored in [RTP mode][`RtcConfig::set_rtp_mode()`] where RTP
    /// packets can arrive out of order.
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
    ///
    /// This setting is ignored in [RTP mode][`RtcConfig::set_rtp_mode()`] where RTP
    /// packets can arrive out of order.
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
    ///
    /// This setting is ignored in [RTP mode][`RtcConfig::set_rtp_mode()`] where RTP
    /// packets can arrive out of order.
    pub fn reordering_size_video(&self) -> usize {
        self.reordering_size_video
    }

    /// Sets the buffer size for outgoing audio packets.
    ///
    /// This must be larger than 0. The value configures an internal ring buffer used as a temporary
    /// holding space between calling [`Writer::write`][crate::media::Writer::write()] and
    /// [`Rtc::poll_output`].
    ///
    /// For audio one call to `write()` typically results in one RTP packet since the entire payload
    /// fits in one. If you can guarantee that every `write()` is a single RTP packet, and is always
    /// followed by a `poll_output()`, it might be possible to set this value to 1. But that would give
    /// no margins for unexpected patterns.
    ///
    /// panics if set to 0.
    pub fn set_send_buffer_audio(mut self, size: usize) -> Self {
        assert!(size > 0);
        self.send_buffer_audio = size;
        self
    }

    /// Returns the setting for audio resend size.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to 50.
    /// assert_eq!(config.send_buffer_audio(), 50);
    /// ```
    pub fn send_buffer_audio(&self) -> usize {
        self.send_buffer_audio
    }

    /// Sets the buffer size for outgoing video packets and resends.
    ///
    /// This must be larger than 0. The value configures an internal ring buffer that is both
    /// used as a temporary holding space between calling [`Writer::write`][crate::media::Writer::write()]
    /// and [`Rtc::poll_output`] as well as for fulfilling resends.
    ///
    /// For video, this buffer is used for more than for audio. First, a call to `write()` often
    /// results in multiple RTP packets since large frames don't fit in one payload. That means the buffer
    /// must be at least as large to hold all those packets. Second, when the remote requests resends (NACK),
    /// those are fulfilled from this buffer. Third, for Bandwidth Estimation (BWE), when probing for
    /// available bandwidth, packets from this buffer are used to do "spurious resends", i.e. we do resends
    /// for packets that were not asked for.
    pub fn set_send_buffer_video(mut self, size: usize) -> Self {
        self.send_buffer_video = size;
        self
    }

    /// Returns the setting for video resend size.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// let config = Rtc::builder();
    ///
    /// // Defaults to 1000.
    /// assert_eq!(config.send_buffer_video(), 1000);
    /// ```
    pub fn send_buffer_video(&self) -> usize {
        self.send_buffer_video
    }

    /// Make the entire Rtc be in RTP mode.
    ///
    /// This means all media, read from [`RtpPacket`] and written to
    /// [`StreamTx::write_rtp`][crate::rtp::StreamTx::write_rtp] are RTP packetized.
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

    /// Enable the [`Event::RawPacket`] event.
    ///
    /// This clones data, and is therefore expensive.
    /// Should not be enabled outside of tests and troubleshooting.
    pub fn enable_raw_packets(mut self, enabled: bool) -> Self {
        self.enable_raw_packets = enabled;
        self
    }

    /// Create a [`Rtc`] from the configuration.
    pub fn build(self) -> Rtc {
        Rtc::new_from_config(self)
    }
}

impl BweConfig {
    fn new(initial_bitrate: Bitrate) -> Self {
        Self {
            initial_bitrate,
            enable_loss_controller: false,
        }
    }
}

impl Default for RtcConfig {
    fn default() -> Self {
        Self {
            local_ice_credentials: None,
            dtls_cert: None,
            fingerprint_verification: true,
            ice_lite: false,
            codec_config: CodecConfig::new_with_defaults(),
            exts: ExtensionMap::standard(),
            stats_interval: None,
            bwe_config: None,
            reordering_size_audio: 15,
            reordering_size_video: 30,
            send_buffer_audio: 50,
            send_buffer_video: 1000,
            rtp_mode: false,
            enable_raw_packets: false,
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

impl fmt::Debug for Rtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rtc").finish()
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
    use std::panic::UnwindSafe;

    use super::*;

    #[test]
    fn rtc_is_send() {
        fn is_send<T: Send>(_t: T) {}
        fn is_sync<T: Sync>(_t: T) {}
        is_send(Rtc::new());
        is_sync(Rtc::new());
    }

    #[test]
    fn rtc_is_unwind_safe() {
        fn is_unwind_safe<T: UnwindSafe>(_t: T) {}
        is_unwind_safe(Rtc::new());
    }

    #[test]
    fn event_is_reasonably_sized() {
        let n = std::mem::size_of::<Event>();
        assert!(n < 450);
    }
}

#[cfg(feature = "_internal_test_exports")]
#[allow(missing_docs)]
pub mod _internal_test_exports;
