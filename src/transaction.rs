//! Transaction-based type-state pattern for str0m API.
//!
//! This module provides a transaction-based API that enforces correct usage at compile time.
//! All mutations go through `rtc.begin(now)`, returning a transaction handle that ensures
//! the user polls to timeout before making additional changes.
//!
//! # Design
//!
//! The transaction pattern provides compile-time enforcement of the poll-to-timeout contract:
//!
//! | Scenario | Enforcement |
//! |----------|-------------|
//! | Mutation after mutation without poll | Compile error (no method on RtcTx) |
//! | Two active transactions | Compile error (double mutable borrow) |
//! | Mixing sub-APIs (e.g., ice + channel) | Compile error (sub-API consumes tx) |
//! | Drop without polling to timeout | Runtime panic (drop impl) |
//! | Forget to reassign `tx = t` | Compiler warning + runtime panic |
//!
//! # Example
//!
//! ```ignore
//! let rtc = Rtc::new();
//!
//! // All mutations start with begin(now)
//! let tx = rtc.begin(now);
//! let mut tx = tx.receive(recv_time, data)?;
//!
//! // poll() consumes tx; Transmit/Event return it, Timeout does not
//! loop {
//!     match tx.poll() {
//!         Output::Timeout(when) => break,           // tx consumed, done
//!         Output::Transmit(t, pkt) => {
//!             tx = t;                                 // must reassign
//!             send(pkt);
//!         }
//!         Output::Event(t, evt) => {
//!             tx = t;                                 // must reassign
//!             handle(evt);
//!         }
//!     }
//! }
//! ```

use std::fmt;
use std::marker::PhantomData;
use std::time::Instant;

use crate::bwe::Bitrate;
use crate::channel::ChannelId;
use crate::media::{KeyframeRequestKind, MediaTime, Mid, Pt, Rid, Writer};
use crate::net::Receive;
use crate::rtp::{ExtensionValues, SeqNo, VideoOrientation};
use crate::rtp_::MidRid;
use crate::Candidate;
use crate::Rtc;
use crate::RtcError;

/// Marker type indicating the transaction is in mutation state.
///
/// In this state, the transaction can perform mutations like `receive()`, `media()`, etc.
pub struct Mutate;

/// Marker type indicating the transaction is in polling state.
///
/// In this state, only `poll()` is available. The transaction must be polled to
/// timeout before it can be dropped.
pub struct Poll;

/// A transaction handle for performing operations on an [`Rtc`] instance.
///
/// The transaction enforces correct API usage through the type system:
/// - After any mutation, the transaction transitions to [`Poll`] state
/// - In [`Poll`] state, the user must poll until timeout
/// - The transaction panics on drop if not properly completed
///
/// # Type States
///
/// - [`Mutate`]: The transaction can perform mutations
/// - [`Poll`]: The transaction must be polled to completion
pub struct RtcTx<'a, State> {
    /// Inner state, wrapped in Option to allow taking during transitions.
    /// This is always Some during normal operation.
    inner: Option<RtcTxInner<'a>>,
    _state: PhantomData<State>,
}

struct RtcTxInner<'a> {
    rtc: &'a mut Rtc,
    now: Instant,
}

impl<'a> RtcTx<'a, Mutate> {
    /// Creates a new transaction in the Mutate state.
    pub(crate) fn new(rtc: &'a mut Rtc, now: Instant) -> Self {
        RtcTx {
            inner: Some(RtcTxInner { rtc, now }),
            _state: PhantomData,
        }
    }

    /// Take the inner state, leaving None behind.
    /// This prevents the Drop from panicking during state transitions.
    fn take_inner(&mut self) -> RtcTxInner<'a> {
        self.inner.take().expect("RtcTx inner state already taken")
    }

    /// Transition to Poll state without any mutation.
    ///
    /// Use this when you only need to advance time without performing any
    /// other operation. Equivalent to the old `handle_input(Input::Timeout(now))`.
    pub fn finish(mut self) -> RtcTx<'a, Poll> {
        let inner = self.take_inner();
        let _ = inner.rtc.do_handle_timeout(inner.now);

        RtcTx {
            inner: Some(inner),
            _state: PhantomData,
        }
    }

    /// Process received network data.
    ///
    /// This is the primary way to handle incoming UDP packets. The `recv_time`
    /// indicates when the packet actually arrived (which may differ from `now`).
    pub fn receive(
        mut self,
        recv_time: Instant,
        data: Receive<'_>,
    ) -> Result<RtcTx<'a, Poll>, RtcError> {
        let inner = self.take_inner();

        // Handle the receive
        inner.rtc.do_handle_receive(recv_time, data)?;
        inner.rtc.do_handle_timeout(inner.now)?;

        Ok(RtcTx {
            inner: Some(inner),
            _state: PhantomData,
        })
    }

    /// Access ICE operations.
    ///
    /// The ICE API consumes the transaction. Call `finish()` to return to Poll state.
    pub fn ice(mut self) -> IceTx<'a> {
        let inner = self.take_inner();
        IceTx {
            rtc: inner.rtc,
            now: inner.now,
        }
    }

    /// Access bandwidth estimation configuration.
    ///
    /// The BWE API consumes the transaction. Call `finish()` to return to Poll state.
    pub fn bwe(mut self) -> BweTx<'a> {
        let inner = self.take_inner();
        BweTx {
            rtc: inner.rtc,
            now: inner.now,
        }
    }

    /// Access a data channel for writing.
    ///
    /// Returns `Err(self)` if the channel doesn't exist or isn't open.
    pub fn channel(mut self, id: ChannelId) -> Result<ChannelTx<'a>, Self> {
        // Check if channel exists - we need to access rtc without taking inner yet
        let inner_ref = self.inner.as_ref().expect("inner state");

        let sctp_stream_id = match inner_ref.rtc.chan.stream_id_by_channel_id(id) {
            Some(id) => id,
            None => return Err(self),
        };

        if !inner_ref.rtc.sctp.is_open(sctp_stream_id) {
            return Err(self);
        }

        // Now take inner
        let inner = self.take_inner();

        Ok(ChannelTx {
            rtc: inner.rtc,
            channel_id: id,
            now: inner.now,
        })
    }

    /// Write media data directly (single-use mutation).
    ///
    /// For more control (RID, audio level, etc.), use `media_writer()` instead.
    pub fn write_media(
        mut self,
        mid: Mid,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: impl Into<Vec<u8>>,
    ) -> Result<RtcTx<'a, Poll>, RtcError> {
        let inner_ref = self.inner.as_ref().expect("inner state");

        if inner_ref.rtc.session.rtp_mode {
            panic!("In rtp_mode use direct_api().stream_tx().write_rtp()");
        }

        // Check if media exists
        if inner_ref.rtc.session.media_by_mid(mid).is_none() {
            return Err(RtcError::NoSenderSource);
        }

        let inner = self.take_inner();

        // Get writer and write
        let writer = Writer::new(&mut inner.rtc.session, mid);
        writer.write(pt, wallclock, rtp_time, data)?;

        inner.rtc.do_handle_timeout(inner.now)?;

        Ok(RtcTx {
            inner: Some(inner),
            _state: PhantomData,
        })
    }

    /// Access a media writer with full configuration options.
    ///
    /// This provides access to both `write()` (frame-level) and `write_rtp()` (packet-level).
    /// Returns `Err(self)` if the media doesn't exist.
    pub fn media_writer(mut self, mid: Mid) -> Result<MediaWriterTx<'a>, Self> {
        let inner_ref = self.inner.as_ref().expect("inner state");

        // Check if media exists
        if inner_ref.rtc.session.media_by_mid(mid).is_none() {
            return Err(self);
        }

        let inner = self.take_inner();

        Ok(MediaWriterTx {
            rtc: inner.rtc,
            mid,
            rid: None,
            start_of_talkspurt: None,
            audio_level: None,
            voice_activity: false,
            video_orientation: None,
            now: inner.now,
        })
    }
}

impl<'a> RtcTx<'a, Poll> {
    fn take_inner(&mut self) -> RtcTxInner<'a> {
        self.inner.take().expect("RtcTx inner state already taken")
    }

    /// Poll the transaction for output.
    ///
    /// Returns one of:
    /// - [`Output::Timeout`]: Transaction complete, you can drop the result
    /// - [`Output::Transmit`]: Send this packet, then continue polling
    /// - [`Output::Event`]: Handle this event, then continue polling
    ///
    /// The transaction handle is returned with `Transmit` and `Event` variants
    /// so you must continue polling. When `Timeout` is returned, the transaction
    /// is complete.
    pub fn poll(mut self) -> Output<'a> {
        let inner = self.take_inner();

        match inner.rtc.do_poll_output() {
            Ok(output) => match output {
                crate::PollOutput::Timeout(t) => {
                    // Transaction complete - don't put inner back
                    Output::Timeout(t)
                }
                crate::PollOutput::Transmit(t) => {
                    // Track bytes transmitted
                    inner.rtc.peer_bytes_tx += t.contents.len() as u64;
                    tracing::trace!("OUT {:?}", t);
                    Output::Transmit(
                        RtcTx {
                            inner: Some(inner),
                            _state: PhantomData,
                        },
                        t,
                    )
                }
                crate::PollOutput::Event(e) => {
                    // Log event at appropriate level
                    match &e {
                        crate::Event::ChannelData(_)
                        | crate::Event::MediaData(_)
                        | crate::Event::RtpPacket(_)
                        | crate::Event::SenderFeedback(_)
                        | crate::Event::MediaEgressStats(_)
                        | crate::Event::MediaIngressStats(_)
                        | crate::Event::PeerStats(_)
                        | crate::Event::ChannelBufferedAmountLow(_)
                        | crate::Event::EgressBitrateEstimate(_) => {
                            tracing::trace!("{:?}", e)
                        }
                        _ => tracing::debug!("{:?}", e),
                    }
                    Output::Event(
                        RtcTx {
                            inner: Some(inner),
                            _state: PhantomData,
                        },
                        e,
                    )
                }
            },
            Err(e) => {
                // On error, don't put inner back (transaction is done)
                tracing::error!("poll_output error: {:?}", e);
                // Return a timeout to signal completion
                Output::Timeout(inner.now)
            }
        }
    }
}

impl<State> Drop for RtcTx<'_, State> {
    fn drop(&mut self) {
        // If inner is still Some, the transaction wasn't completed properly
        if self.inner.is_some() && !std::thread::panicking() {
            panic!(
                "RtcTx dropped without polling to completion. \
                 You must poll() until Output::Timeout is returned."
            );
        }
    }
}

/// Output from polling a transaction.
#[allow(clippy::large_enum_variant)]
pub enum Output<'a> {
    /// Transaction is complete. The timeout indicates when to call `begin()` again.
    Timeout(Instant),

    /// Data to transmit. Continue polling after sending.
    Transmit(RtcTx<'a, Poll>, crate::net::Transmit),

    /// Event occurred. Continue polling after handling.
    Event(RtcTx<'a, Poll>, crate::Event),
}

impl fmt::Debug for Output<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Output::Timeout(t) => f.debug_tuple("Timeout").field(t).finish(),
            Output::Transmit(_, t) => f.debug_tuple("Transmit").field(t).finish(),
            Output::Event(_, e) => f.debug_tuple("Event").field(e).finish(),
        }
    }
}

// ============================================================================
// Sub-API transaction wrappers
// ============================================================================

/// ICE operations transaction wrapper.
///
/// Add local and remote ICE candidates, then call `finish()` to return to Poll state.
pub struct IceTx<'a> {
    rtc: &'a mut Rtc,
    now: Instant,
}

impl<'a> IceTx<'a> {
    /// Add a local ICE candidate.
    pub fn add_local(self, candidate: Candidate) -> Self {
        self.rtc.add_local_candidate(candidate);
        self
    }

    /// Add a remote ICE candidate.
    pub fn add_remote(self, candidate: Candidate) -> Self {
        self.rtc.add_remote_candidate(candidate);
        self
    }

    /// Finish ICE operations and return to Poll state.
    pub fn finish(self) -> RtcTx<'a, Poll> {
        let _ = self.rtc.do_handle_timeout(self.now);

        RtcTx {
            inner: Some(RtcTxInner {
                rtc: self.rtc,
                now: self.now,
            }),
            _state: PhantomData,
        }
    }
}

/// Bandwidth estimation transaction wrapper.
pub struct BweTx<'a> {
    rtc: &'a mut Rtc,
    now: Instant,
}

impl<'a> BweTx<'a> {
    /// Set the desired bitrate for bandwidth estimation.
    pub fn set_desired_bitrate(self, desired_bitrate: Bitrate) -> Self {
        self.rtc.session.set_bwe_desired_bitrate(desired_bitrate);
        self
    }

    /// Reset BWE with a new initial bitrate.
    pub fn reset(self, init_bitrate: Bitrate) -> Self {
        self.rtc.session.reset_bwe(init_bitrate);
        self
    }

    /// Finish BWE operations and return to Poll state.
    pub fn finish(self) -> RtcTx<'a, Poll> {
        let _ = self.rtc.do_handle_timeout(self.now);

        RtcTx {
            inner: Some(RtcTxInner {
                rtc: self.rtc,
                now: self.now,
            }),
            _state: PhantomData,
        }
    }
}

/// Channel operations transaction wrapper.
pub struct ChannelTx<'a> {
    rtc: &'a mut Rtc,
    channel_id: ChannelId,
    now: Instant,
}

impl<'a> ChannelTx<'a> {
    /// Write data to the channel.
    pub fn write(self, binary: bool, data: &[u8]) -> Self {
        if let Some(mut channel) = self.rtc.channel(self.channel_id) {
            let _ = channel.write(binary, data);
        }
        self
    }

    /// Finish channel operations and return to Poll state.
    pub fn finish(self) -> RtcTx<'a, Poll> {
        let _ = self.rtc.do_handle_timeout(self.now);

        RtcTx {
            inner: Some(RtcTxInner {
                rtc: self.rtc,
                now: self.now,
            }),
            _state: PhantomData,
        }
    }
}

/// Media writer transaction wrapper with full configuration options.
///
/// This mirrors the builder pattern of the original `Writer` API.
pub struct MediaWriterTx<'a> {
    rtc: &'a mut Rtc,
    mid: Mid,
    rid: Option<Rid>,
    start_of_talkspurt: Option<bool>,
    audio_level: Option<i8>,
    voice_activity: bool,
    video_orientation: Option<VideoOrientation>,
    now: Instant,
}

impl<'a> MediaWriterTx<'a> {
    /// Set the RID for simulcast.
    pub fn rid(mut self, rid: Rid) -> Self {
        self.rid = Some(rid);
        self
    }

    /// Set audio level for the RTP header extension.
    pub fn audio_level(mut self, audio_level: i8, voice_activity: bool) -> Self {
        self.audio_level = Some(audio_level);
        self.voice_activity = voice_activity;
        self
    }

    /// Indicate start of talkspurt for audio.
    pub fn start_of_talkspurt(mut self, start: bool) -> Self {
        self.start_of_talkspurt = Some(start);
        self
    }

    /// Set video orientation for the RTP header extension.
    pub fn video_orientation(mut self, orientation: VideoOrientation) -> Self {
        self.video_orientation = Some(orientation);
        self
    }

    /// Write media data and transition to Poll state.
    ///
    /// # Panics
    ///
    /// Panics if in RTP mode. Use `write_rtp()` for packet-level writes.
    pub fn write(
        self,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: impl Into<Vec<u8>>,
    ) -> Result<RtcTx<'a, Poll>, RtcError> {
        if self.rtc.session.rtp_mode {
            panic!("write() not available in RTP mode. Use write_rtp() for packet-level writes.");
        }

        // Build the writer with all configured options
        let mut writer = Writer::new(&mut self.rtc.session, self.mid);

        if let Some(rid) = self.rid {
            writer = writer.rid(rid);
        }

        if let Some(audio_level) = self.audio_level {
            writer = writer.audio_level(audio_level, self.voice_activity);
        }

        if let Some(start) = self.start_of_talkspurt {
            writer = writer.start_of_talkspurt(start);
        }

        if let Some(orientation) = self.video_orientation {
            writer = writer.video_orientation(orientation);
        }

        writer.write(pt, wallclock, rtp_time, data)?;

        self.rtc.do_handle_timeout(self.now)?;

        Ok(RtcTx {
            inner: Some(RtcTxInner {
                rtc: self.rtc,
                now: self.now,
            }),
            _state: PhantomData,
        })
    }

    /// Write an RTP packet directly (RTP mode only).
    ///
    /// This is for use in RTP mode where you want to write raw RTP packets.
    /// The packet is queued and will be transmitted when polling.
    ///
    /// # Panics
    ///
    /// Panics if not in RTP mode. Use `write()` for frame-level media.
    #[allow(clippy::too_many_arguments)]
    pub fn write_rtp(
        self,
        pt: Pt,
        seq_no: SeqNo,
        time: u32,
        wallclock: Instant,
        marker: bool,
        ext_vals: ExtensionValues,
        nackable: bool,
        payload: Vec<u8>,
    ) -> Result<RtcTx<'a, Poll>, RtcError> {
        if !self.rtc.session.rtp_mode {
            panic!("write_rtp() requires RTP mode. Use write() for frame-level media.");
        }

        let midrid = MidRid(self.mid, self.rid);
        let stream = self
            .rtc
            .session
            .streams
            .stream_tx_by_midrid(midrid)
            .ok_or(RtcError::NoSenderSource)?;

        stream
            .write_rtp(
                pt, seq_no, time, wallclock, marker, ext_vals, nackable, payload,
            )
            .map_err(|e| RtcError::Packet(self.mid, pt, e))?;

        self.rtc.do_handle_timeout(self.now)?;

        Ok(RtcTx {
            inner: Some(RtcTxInner {
                rtc: self.rtc,
                now: self.now,
            }),
            _state: PhantomData,
        })
    }

    /// Request a keyframe from the remote peer.
    pub fn request_keyframe(
        self,
        rid: Option<Rid>,
        kind: KeyframeRequestKind,
    ) -> Result<RtcTx<'a, Poll>, RtcError> {
        let mut writer = Writer::new(&mut self.rtc.session, self.mid);

        if let Some(r) = self.rid {
            writer = writer.rid(r);
        }

        writer.request_keyframe(rid, kind)?;

        self.rtc.do_handle_timeout(self.now)?;

        Ok(RtcTx {
            inner: Some(RtcTxInner {
                rtc: self.rtc,
                now: self.now,
            }),
            _state: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "RtcTx dropped without polling")]
    fn test_panic_on_incomplete_drop_mutate() {
        crate::init_crypto_default();

        let mut rtc = Rtc::new();
        let _tx = rtc.begin(Instant::now());
        // Drop without calling finish() or any mutation - should panic
    }

    #[test]
    #[should_panic(expected = "RtcTx dropped without polling")]
    fn test_panic_on_incomplete_drop_poll() {
        crate::init_crypto_default();

        let mut rtc = Rtc::new();
        let tx = rtc.begin(Instant::now());
        let _tx = tx.finish(); // Transitions to Poll but doesn't poll to completion
                               // Drop without polling - should panic
    }

    #[test]
    #[should_panic(expected = "RtcTx dropped without polling")]
    fn test_panic_after_ice_finish() {
        crate::init_crypto_default();

        let mut rtc = Rtc::new();
        let tx = rtc.begin(Instant::now());
        let ice_tx = tx.ice();
        let _tx = ice_tx.finish(); // Returns Poll state but not polled
                                   // Should panic on drop
    }

    #[test]
    #[should_panic(expected = "RtcTx dropped without polling")]
    fn test_panic_after_bwe_finish() {
        crate::init_crypto_default();

        let mut rtc = Rtc::new();
        let tx = rtc.begin(Instant::now());
        let bwe_tx = tx.bwe();
        let _tx = bwe_tx.finish(); // Returns Poll state but not polled
                                   // Should panic on drop
    }
}
