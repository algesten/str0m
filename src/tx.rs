//! Transaction-based type-state pattern for str0m API.

use std::fmt;
use std::marker::PhantomData;
use std::thread;
use std::time::Instant;

use crate::bwe::{Bitrate, Bwe};
use crate::change::{DirectApi, SdpApi};
use crate::channel::{Channel, ChannelId};
use crate::ice_::Ice;
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
    ret: Option<Result<(), RtcError>>,
}

impl<'a> RtcTx<'a, Mutate> {
    /// Creates a new transaction in the Mutate state.
    pub(crate) fn new(rtc: &'a mut Rtc, ret: Result<(), RtcError>) -> Self {
        RtcTx {
            inner: Some(RtcTxInner {
                rtc,
                ret: Some(ret),
            }),
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
    /// other operation.
    pub fn finish(mut self) -> Result<RtcTx<'a, Poll>, RtcError> {
        let mut inner = self.take_inner();

        // Surface delayed result from Rtc::begin()
        // UNWRAP: is correct since there must be a delayed result.
        inner.ret.take().unwrap()?;

        Ok(RtcTx {
            inner: Some(inner),
            _state: PhantomData,
        })
    }

    /// ICE operations.
    pub fn ice(mut self) -> Ice<'a> {
        todo!()
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
    /// let mid_audio = changes.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    /// let mid_video = changes.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
    ///
    /// let (offer, pending) = changes.apply().unwrap();
    /// let json = serde_json::to_vec(&offer).unwrap();
    ///
    /// // Send json OFFER to remote peer. Receive an answer back.
    /// let answer: SdpAnswer = todo!();
    ///
    /// rtc.sdp_api().accept_answer(pending, answer).unwrap();
    /// ```
    pub fn sdp_api(self) -> SdpApi<'a> {
        todo!()
    }

    /// Makes direct changes to the Rtc session.
    ///
    /// This is a low level API. For "normal" use via SDP, see [`Rtc::sdp_api()`].
    pub fn direct_api(self) -> DirectApi<'a> {
        todo!()
    }

    /// Process received network data.
    ///
    /// This is how to handle incoming UDP packets.
    pub fn receive(mut self, data: Receive<'_>) -> Result<RtcTx<'a, Poll>, RtcError> {
        let mut inner = self.take_inner();

        // Surface delayed result from Rtc::begin()
        // UNWRAP: is correct since there must be a delayed result.
        inner.ret.take().unwrap()?;

        // Handle the receive
        inner.rtc.handle_receive(data)?;

        Ok(RtcTx {
            inner: Some(inner),
            _state: PhantomData,
        })
    }

    /// Configure the Bandwidth Estimate (BWE) subsystem.
    ///
    /// Only relevant if BWE was enabled in the [`RtcConfig::enable_bwe()`]
    pub fn bwe(mut self) -> Bwe<'a> {
        todo!()
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
    pub fn channel(mut self, id: ChannelId) -> Result<Channel<'a>, Self> {
        todo!()
    }

    /// Send outgoing media data (frames) or request keyframes.
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
    /// This is a frame level API: For RTP level see [`DirectApi::stream_tx()`]
    /// and [`DirectApi::stream_rx()`].
    ///
    pub fn writer(mut self, mid: Mid) -> Result<Writer<'a>, Self> {
        todo!()
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

        // Invariant: handle_Timeout error must be surfaced by now.
        assert!(inner.ret.is_none());

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
