use std::time::Instant;

use crate::media::KeyframeRequestKind;
use crate::rtp::SenderInfo;
use crate::rtp::Ssrc;
use crate::util::already_happened;

use super::register::ReceiverRegister;
use super::rr_interval;

/// Incoming encoded stream.
///
/// A stream is a primary SSRC + optional RTX SSRC.
#[derive(Debug)]
pub(crate) struct StreamRx {
    /// Unique idenfier of the remote stream.
    ///
    /// If the remote changes the SSRC, we will create a new stream, not change this id.
    ssrc: Ssrc,

    /// Identifier of a resend (RTX) stream. This can be set later, once we discover it.
    rtx: Option<Ssrc>,

    /// Timestamp when we got some indication of remote using this stream.
    last_used: Instant,

    /// Last received sender info.
    sender_info: Option<(Instant, SenderInfo)>,

    /// Register of received packets. For NACK handling.
    ///
    /// Set on first ever packet.
    register: Option<ReceiverRegister>,

    /// If we have a pending keyframe request to send.
    pending_request_keyframe: Option<KeyframeRequestKind>,

    /// Last time we produced regular feedback RR.
    last_receiver_report: Instant,

    /// Statistics of incoming data.
    stats: StreamRxStats,
}

impl StreamRx {
    pub fn new(ssrc: Ssrc) -> Self {
        debug!("Create StreamRx for SSRC: {}", ssrc);

        StreamRx {
            ssrc,
            rtx: None,
            last_used: already_happened(),
            sender_info: None,
            register: None,
            pending_request_keyframe: None,
            last_receiver_report: already_happened(),
            stats: StreamRxStats::default(),
        }
    }

    pub fn set_rtx_ssrc(&mut self, rtx: Ssrc) {
        if self.rtx != Some(rtx) {
            debug!("SSRC {} associated with RTX: {}", self.ssrc, rtx);
            self.rtx = Some(rtx);
        }
    }

    pub(crate) fn request_keyframe(&mut self, kind: KeyframeRequestKind) {
        self.pending_request_keyframe = Some(kind);
    }

    pub(crate) fn receiver_report_at(&self) -> Instant {
        let is_audio = self.rtx.is_none(); // this is maybe not correct, but it's all we got.
        self.last_receiver_report + rr_interval(is_audio)
    }

    pub(crate) fn stats(&self) -> &StreamRxStats {
        &self.stats
    }
}

/// Holder of stats.
#[derive(Debug, Default)]
pub(crate) struct StreamRxStats {
    fir_seq_no: u8,
    bytes: u64,
    packets: u64,
    firs: u64,
    plis: u64,
    nacks: u64,
    rtt: Option<f32>,
    loss: Option<f32>,
}
