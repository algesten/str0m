#![allow(unused_variables)]
use std::time::Instant;

use crate::media::KeyframeRequestKind;
use crate::rtp::Ssrc;
use crate::{Rtc, RtcError};

/// Wrapper for the RTP API.
pub struct RtpApi<'a>(pub(crate) &'a mut Rtc);

impl<'a> RtpApi<'a> {
    /// Allocate a new SSRC that is not in use in the session already.
    pub fn new_ssrc(&mut self) -> Ssrc {
        todo!()
    }

    /// Allow incoming traffic from remote peer for the given SSRC.
    ///
    /// The first time we ever discover a new SSRC, we emit the [`Event::RtpData`] with the bool flag
    /// `initial: true`. No more packets will be handled unless we call `allow_stream_rx` for the incoming
    /// SSRC.
    ///
    /// Can be called multiple times if the `rtx` is discovered later via RTP header extensions.
    pub fn allow_stream_rx(&mut self, ssrc: Ssrc, rtx: Option<Ssrc>) {
        todo!()
    }

    /// Declare the intention to send data using the given SSRC.
    ///
    /// * The resend RTX is optional and only necessary for video.
    ///
    /// Can be called multiple times without changing any internal state.
    pub fn declare_stream_tx(&mut self, ssrc: Ssrc, rtx: Option<Ssrc>) {
        todo!()
    }

    /// Write RTP packet to a send stream.
    ///
    /// * The stream (SSRC) must be declared beforehand using [`new_stream_tx`].
    /// * For wallclock see below.
    /// * Packet is the RTP packet including header. This needs to have all the wanted extension headers.
    ///   Specifically RtpMid, RtpStreamId and RtpRepairedStreamId should be set correctly for situations
    ///   where the SSRC is not communicated in a side channel.
    /// * Nackable indicates whether this packet can be nacked by the remote and resent. This is always
    ///   false for audio, but should also be set to false when the RTP payload is a discardable temporal
    ///   layer (such as layer L1 in VP8).
    ///
    /// Regarding `wallclock` and `rtp_time`, the wallclock is the real world time that corresponds to
    /// the `MediaTime`. For an SFU, this can be hard to know, since RTP packets typically only
    /// contain the media time (RTP time). In the simplest SFU setup, the wallclock could simply
    /// be the arrival time of the incoming RTP data (see
    /// [`MediaData::network_time`][crate::media::MediaData]). For better synchronization the SFU
    /// probably needs to weigh in clock drifts and data provided via the statistics.
    pub fn write_rtp(
        &mut self,
        ssrc: Ssrc,
        wallclock: Instant,
        packet: &[u8],
        nackable: bool,
    ) -> Result<(), RtcError> {
        todo!()
    }

    /// Request a keyframe for some incoming data.
    ///
    /// * SSRC the identifier of the remote stream to request a keyframe for.
    /// * kind PLI or FIR.
    pub fn request_keyframe(
        &mut self,
        ssrc: Ssrc,
        kind: KeyframeRequestKind,
    ) -> Result<(), RtcError> {
        todo!()
    }
}
