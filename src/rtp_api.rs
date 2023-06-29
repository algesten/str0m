use std::time::Instant;

use crate::media::KeyframeRequestKind;
use crate::rtp::Ssrc;
use crate::{Rtc, RtcError};

/// Wrapper for the RTP API.
pub struct RtpApi<'a>(pub(crate) &'a mut Rtc);

/// Sender id for a RTP send stream.
pub struct SenderId(u64);

impl<'a> RtpApi<'a> {
    pub fn new_ssrc(&mut self) -> Ssrc {
        todo!()
    }

    /// Create a new sender for outgoing RTP.
    ///
    /// * The SSRC must be allocated beforehand using [`allocate_ssrc`].
    /// * The resend RTX is optional and only necessary for video.
    pub fn new_sender(&mut self, ssrc: Ssrc, rtx: Option<Ssrc>) -> SenderId {
        todo!()
    }

    /// Write outgoing RTP for a sender.
    ///
    /// * The sender must be created using [`new_sender`].
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
        sid: SenderId,
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
