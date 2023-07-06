use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use crate::rtp::RtpHeader;
use crate::rtp::SeqNo;
use crate::rtp::Ssrc;
use crate::rtp::{MediaTime, Pt};

pub use self::receive::StreamRx;
pub use self::send::StreamTx;

mod receive;
mod register;
mod rtx_cache;
mod send;

// Time between regular receiver reports.
// https://www.rfc-editor.org/rfc/rfc8829#section-5.1.2
// Should technically be 4 seconds according to spec, but libWebRTC
// expects video to be every second, and audio every 5 seconds.
const RR_INTERVAL_VIDEO: Duration = Duration::from_millis(1000);
const RR_INTERVAL_AUDIO: Duration = Duration::from_millis(5000);

fn rr_interval(audio: bool) -> Duration {
    if audio {
        RR_INTERVAL_AUDIO
    } else {
        RR_INTERVAL_VIDEO
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct StreamPacket {
    /// Extended sequence number to avoid having to deal with ROC.
    pub seq_no: SeqNo,

    /// Extended RTP time in the clock frequency of the codec. To avoid dealing with ROC.
    pub time: MediaTime,

    /// Parsed RTP header.
    pub header: RtpHeader,

    /// RTP payload. This contains no header.
    pub payload: Vec<u8>,

    /// Whether this packet can be nacked. This is always false for audio,
    /// but might also be false for discardable frames when using temporal encoding
    /// as in a VP8 simulcast situation.
    pub nackable: bool,

    /// This timestamp has nothing to do with RTP itself. For outgoing packets, this is when
    /// the packet was first handed over to str0m and enqueued in the outgoing send buffers.
    /// For incoming packets it's the time we received the network packet.
    pub timestamp: Instant,
}

/// Holder of incoming/outgoing encoded streams.
///
/// Each encoded stream is uniquely identified by an SSRC. The concept of mid/rid sits on the Media
/// level together with the ability to translate a mid/rid to an encoded stream.
#[derive(Debug, Default)]
pub struct Streams {
    /// All incoming encoded streams.
    streams_rx: HashMap<Ssrc, StreamRx>,

    /// All outgoing encoded streams.
    streams_tx: HashMap<Ssrc, StreamTx>,
}

impl Streams {
    /// Allow incoming traffic from remote peer for the given SSRC.
    ///
    /// The first time we ever discover a new SSRC, we emit the [`Event::RtpData`] with the bool flag
    /// `initial: true`. No more packets will be handled unless we call `allow_stream_rx` for the incoming
    /// SSRC.
    ///
    /// Can be called multiple times if the `rtx` is discovered later via RTP header extensions.
    pub fn expect_stream_rx(&mut self, ssrc: Ssrc, rtx: Option<Ssrc>) {
        let stream = self
            .streams_rx
            .entry(ssrc)
            .or_insert_with(|| StreamRx::new(ssrc));

        if let Some(rtx) = rtx {
            stream.set_rtx_ssrc(rtx);
        }
    }

    /// Obtain a receive stream.
    ///
    /// The stream must first be declared usig [`expect_stream_rx`].
    pub fn stream_rx(&mut self, ssrc: &Ssrc) -> Option<&mut StreamRx> {
        self.streams_rx.get_mut(ssrc)
    }

    /// Declare the intention to send data using the given SSRC.
    ///
    /// * The resend RTX is optional but necessary to do resends. str0m does not do
    ///   resends without RTX.
    ///
    /// Can be called multiple times without changing any internal state. However
    /// the RTX value is only picked up the first ever time we see a new SSRC.
    pub fn declare_stream_tx(&mut self, ssrc: Ssrc, pt: Pt, rtx: Option<Ssrc>, rtx_pt: Option<Pt>) {
        assert_eq!(rtx.is_some(), rtx_pt.is_some(), "rtx requires rtx_pt");

        let stream = self
            .streams_tx
            .entry(ssrc)
            .or_insert_with(|| StreamTx::new(ssrc, pt, rtx, rtx_pt));

        stream.set_rtx(rtx, rtx_pt);
    }

    /// Obtain a send stream.
    ///
    /// The stream must first be declared usig [`declare_stream_tx`].
    pub fn stream_tx(&mut self, ssrc: &Ssrc) -> Option<&mut StreamTx> {
        self.streams_tx.get_mut(ssrc)
    }

    pub(crate) fn regular_feedback_at(&self) -> Option<Instant> {
        let r = self.streams_rx.values().map(|s| s.receiver_report_at());
        let s = self.streams_tx.values().map(|s| s.sender_report_at());
        r.chain(s).min()
    }

    pub(crate) fn need_nack(&mut self) -> bool {
        self.streams_rx.values_mut().any(|s| s.has_nack())
    }

    pub(crate) fn is_receiving(&self) -> bool {
        !self.streams_rx.is_empty()
    }
}
