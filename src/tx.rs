//! Transaction-based type-state pattern for str0m API.

use std::fmt;
use std::marker::PhantomData;
use std::thread;
use std::time::Instant;

use crate::bwe::Bwe;
use crate::change::{DirectApi, SdpApi};
use crate::channel::{Channel, ChannelId};
use crate::media::{Mid, Writer};
use crate::net::Receive;
use crate::rtp::{ExtensionValues, SeqNo, Ssrc};
use crate::Pt;
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

impl<State> fmt::Debug for RtcTx<'_, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtcTx").finish_non_exhaustive()
    }
}

pub(crate) struct RtcTxInner<'a> {
    pub(crate) rtc: &'a mut Rtc,
}

impl<'a> RtcTx<'a, Mutate> {
    /// Creates a new transaction in the Mutate state.
    pub(crate) fn new(rtc: &'a mut Rtc) -> Self {
        RtcTx {
            inner: Some(RtcTxInner { rtc }),
            _state: PhantomData,
        }
    }

    /// Take the inner state, leaving None behind.
    /// This prevents the Drop from panicking during state transitions.
    fn take_inner(&mut self) -> RtcTxInner<'a> {
        self.inner.take().expect("RtcTx inner state already taken")
    }

    /// Consume self and return the inner parts for sub-API wrappers.
    /// The wrapper is responsible for calling `into_poll` when done.
    pub(crate) fn into_inner(mut self) -> RtcTxInner<'a> {
        self.take_inner()
    }

    /// Create a Poll state transaction from inner parts.
    /// Used by sub-API wrappers to return Poll state after finish().
    pub(crate) fn from_inner(inner: RtcTxInner<'a>) -> RtcTx<'a, Poll> {
        RtcTx {
            inner: Some(inner),
            _state: PhantomData,
        }
    }

    /// Transition to Poll state without any mutation.
    ///
    /// Use this when you only need to advance time without performing any
    /// other operation.
    pub fn finish(mut self) -> RtcTx<'a, Poll> {
        let inner = self.take_inner();

        RtcTx {
            inner: Some(inner),
            _state: PhantomData,
        }
    }

    /// Make changes to the Rtc session via SDP.
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// # use str0m::Rtc;
    /// # use str0m::media::{MediaKind, Direction};
    /// # use str0m::change::SdpAnswer;
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.begin(Instant::now()).sdp_api();
    /// let mid_audio = changes.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    /// let mid_video = changes.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
    ///
    /// let (offer, pending, tx) = changes.apply().unwrap();
    /// let json = serde_json::to_vec(&offer).unwrap();
    /// // poll tx to completion...
    ///
    /// // Send json OFFER to remote peer. Receive an answer back.
    /// let answer: SdpAnswer = todo!();
    ///
    /// let tx = rtc.begin(Instant::now()).sdp_api().accept_answer(pending, answer).unwrap();
    /// // poll tx to completion...
    /// ```
    pub fn sdp_api(self) -> SdpApi<'a> {
        SdpApi::new(self)
    }

    /// Makes direct changes to the Rtc session.
    ///
    /// This is a low level API. For "normal" use via SDP, see [`RtcTx::sdp_api()`].
    pub fn direct_api(self) -> DirectApi<'a> {
        DirectApi::new(self)
    }

    /// Process received network data.
    ///
    /// This is how to handle incoming UDP packets.
    pub fn receive(mut self, data: Receive<'_>) -> Result<RtcTx<'a, Poll>, RtcError> {
        let inner = self.take_inner();

        // Handle the receive
        inner.rtc.handle_receive(data)?;

        Ok(RtcTx {
            inner: Some(inner),
            _state: PhantomData,
        })
    }

    /// Configure the Bandwidth Estimate (BWE) subsystem.
    ///
    /// Only relevant if BWE was enabled in the [`RtcConfig::enable_bwe()`][crate::RtcConfig::enable_bwe()]
    pub fn bwe(self) -> Bwe<'a> {
        Bwe::new(self)
    }

    /// Obtain handle for writing to a data channel.
    ///
    /// This is first available when a [`ChannelId`] is advertised via
    /// [`Event::ChannelOpen`][crate::Event::ChannelOpen].
    /// The function returns `Err(self)` also for IDs from
    /// [`SdpApi::add_channel()`][crate::change::SdpApi::add_channel()].
    ///
    /// Incoming channel data is via the
    /// [`Event::ChannelData`][crate::Event::ChannelData] event.
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// # use str0m::{Rtc, channel::ChannelId};
    /// let mut rtc = Rtc::new();
    ///
    /// let cid: ChannelId = todo!(); // obtain channel id from Event::ChannelOpen
    /// let channel = rtc.begin(Instant::now()).channel(cid).unwrap();
    /// // write data channel data...
    /// // channel.finish() to get RtcTx<Poll>
    /// ```
    pub fn channel(self, id: ChannelId) -> Result<Channel<'a>, Self> {
        // Look up the SCTP stream id for the channel and check if it's open
        let sctp_stream_id = {
            let inner = self.inner.as_ref().expect("inner not taken");
            let Some(stream_id) = inner.rtc.chan.stream_id_by_channel_id(id) else {
                return Err(self);
            };
            if !inner.rtc.sctp.is_open(stream_id) {
                return Err(self);
            }
            stream_id
        };

        Ok(Channel::new(sctp_stream_id, self))
    }

    /// Send outgoing media data (frames) or request keyframes.
    ///
    /// Returns `Err(self)` if the direction isn't sending (`sendrecv` or `sendonly`).
    ///
    /// ```no_run
    /// # use std::time::Instant;
    /// # use str0m::Rtc;
    /// # use str0m::media::{MediaData, Mid};
    /// # use str0m::format::PayloadParams;
    /// let mut rtc = Rtc::new();
    ///
    /// // add candidates, do SDP negotiation
    /// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
    ///
    /// // Writer for this mid.
    /// let writer = rtc.begin(Instant::now()).writer(mid).unwrap();
    ///
    /// // Get incoming media data from another peer
    /// let data: MediaData = todo!();
    ///
    /// // Match incoming PT to an outgoing PT.
    /// let pt = writer.match_params(data.params).unwrap();
    ///
    /// let tx = writer.write(pt, data.network_time, data.time, data.data).unwrap();
    /// // poll tx to completion...
    /// ```
    ///
    /// This is a frame level API: For RTP level see [`DirectApi::stream_tx()`]
    /// and [`DirectApi::stream_rx()`].
    ///
    pub fn writer(self, mid: Mid) -> Result<Writer<'a>, Self> {
        // Check if the direction allows sending
        let can_write = {
            let inner = self.inner.as_ref().expect("inner not taken");
            inner
                .rtc
                .session
                .media_by_mid(mid)
                .map(|m| m.direction().is_sending())
                .unwrap_or(false)
        };

        if can_write {
            Ok(Writer::new(self, mid))
        } else {
            Err(self)
        }
    }

    /// Write an RTP packet to a send stream.
    ///
    /// This is the RTP-level API for sending media. For frame-level API, see [`Self::writer()`].
    ///
    /// The stream must first be declared using
    /// [`DirectApi::declare_stream_tx`][crate::change::DirectApi::declare_stream_tx].
    ///
    /// # Arguments
    ///
    /// * `ssrc` - The SSRC of the stream to write to.
    /// * `pt` - Payload type. Declared in the Media this encoded stream belongs to.
    /// * `seq_no` - Sequence number to use for this packet.
    /// * `time` - Time in whatever the clock rate is for the media in question (normally 90_000 for video
    ///            and 48_000 for audio).
    /// * `wallclock` - Real world time that corresponds to the media time in the RTP packet.
    /// * `marker` - Whether to "mark" this packet. Usually done for the last packet of a frame.
    /// * `ext_vals` - The RTP header extension values to set.
    /// * `nackable` - Whether we should respond this packet for incoming NACK from the remote peer.
    /// * `payload` - RTP packet payload, without header.
    #[allow(clippy::too_many_arguments)]
    pub fn write_rtp(
        mut self,
        ssrc: Ssrc,
        pt: Pt,
        seq_no: SeqNo,
        time: u32,
        wallclock: Instant,
        marker: bool,
        ext_vals: ExtensionValues,
        nackable: bool,
        payload: Vec<u8>,
    ) -> Result<RtcTx<'a, Poll>, RtcError> {
        let inner = self.take_inner();

        // Get the stream and write the RTP packet
        let stream = inner
            .rtc
            .session
            .streams
            .stream_tx(&ssrc)
            .ok_or(RtcError::UnknownSsrc(ssrc))?;

        stream
            .write_rtp(
                pt, seq_no, time, wallclock, marker, ext_vals, nackable, payload,
            )
            .map_err(RtcError::RtpWrite)?;

        Ok(RtcTx {
            inner: Some(inner),
            _state: PhantomData,
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
    pub fn poll(mut self) -> Result<Output<'a>, RtcError> {
        let inner = self.take_inner();

        match inner.rtc.poll_output()? {
            crate::PollOutput::Timeout(t) => {
                // Transaction complete - don't put inner back
                Ok(Output::Timeout(t))
            }
            crate::PollOutput::Transmit(t) => {
                // Track bytes transmitted
                inner.rtc.peer_bytes_tx += t.contents.len() as u64;
                tracing::trace!("OUT {:?}", t);
                Ok(Output::Transmit(
                    RtcTx {
                        inner: Some(inner),
                        _state: PhantomData,
                    },
                    t,
                ))
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
                Ok(Output::Event(
                    RtcTx {
                        inner: Some(inner),
                        _state: PhantomData,
                    },
                    e,
                ))
            }
        }
    }
}

impl<State> Drop for RtcTx<'_, State> {
    fn drop(&mut self) {
        // If inner is still Some, the transaction wasn't completed properly
        if self.inner.is_some() && !thread::panicking() {
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
        let tx = rtc.begin(Instant::now()).expect("begin");
        let _tx = tx.finish(); // Transitions to Poll but doesn't poll to completion
                               // Drop without polling - should panic
    }

    #[test]
    #[should_panic(expected = "RtcTx dropped without polling")]
    fn test_panic_after_bwe_finish() {
        crate::init_crypto_default();

        let mut rtc = Rtc::new();
        let tx = rtc.begin(Instant::now()).expect("begin");
        let bwe_tx = tx.bwe();
        let _tx = bwe_tx.finish(); // Returns Poll state but not polled
                                   // Should panic on drop
    }
}
