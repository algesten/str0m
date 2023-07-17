use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use std::time::Instant;

use crate::media::KeyframeRequest;
use crate::rtp_::Ssrc;
use crate::rtp_::{MediaTime, Pt};
use crate::rtp_::{Mid, Rid, SeqNo};
use crate::rtp_::{Rtcp, RtpHeader};

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

    /// Payload type for this packet.
    pt: Pt,

    /// Extended RTP time in the clock frequency of the codec. To avoid dealing with ROC.
    ///
    /// For a newly scheduled outgoing packet, the clock_rate is not correctly set until
    /// we do the poll_output().
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
pub(crate) struct Streams {
    /// All incoming encoded streams.
    streams_rx: HashMap<Ssrc, StreamRx>,

    /// All outgoing encoded streams.
    streams_tx: HashMap<Ssrc, StreamTx>,
}

impl Streams {
    pub fn expect_stream_rx(&mut self, ssrc: Ssrc, rtx: Option<Ssrc>, mid: Mid, rid: Option<Rid>) {
        let stream = self
            .streams_rx
            .entry(ssrc)
            .or_insert_with(|| StreamRx::new(ssrc, mid, rid));

        if let Some(rtx) = rtx {
            stream.set_rtx_ssrc(rtx);
        }
    }

    pub fn declare_stream_tx(
        &mut self,
        ssrc: Ssrc,
        rtx: Option<Ssrc>,
        mid: Mid,
        rid: Option<Rid>,
    ) -> &mut StreamTx {
        self.streams_tx
            .entry(ssrc)
            .or_insert_with(|| StreamTx::new(ssrc, rtx, mid, rid))
    }

    pub fn stream_rx(&mut self, ssrc: &Ssrc) -> Option<&mut StreamRx> {
        self.streams_rx.get_mut(ssrc)
    }

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

    pub(crate) fn handle_timeout(
        &mut self,
        now: Instant,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) {
        for stream in self.streams_rx.values_mut() {
            stream.maybe_create_keyframe_request(sender_ssrc, feedback);
        }

        todo!()
    }

    pub(crate) fn main_ssrc_rx_for(&self, ssrc_rtx: Ssrc) -> Option<Ssrc> {
        self.streams_rx
            .values()
            .find(|s| s.rtx() == Some(ssrc_rtx))
            .map(|s| s.ssrc())
    }

    pub(crate) fn tx_by_mid_rid(&mut self, mid: Mid, rid: Option<Rid>) -> Option<&mut StreamTx> {
        self.streams_tx
            .values_mut()
            .find(|s| s.mid() == mid && (rid.is_none() || s.rid() == rid))
    }

    pub(crate) fn rx_by_mid_rid(&mut self, mid: Mid, rid: Option<Rid>) -> Option<&mut StreamRx> {
        self.streams_rx
            .values_mut()
            .find(|s| s.mid() == mid && (rid.is_none() || s.rid() == rid))
    }

    pub(crate) fn poll_keyframe_request(&mut self) -> Option<KeyframeRequest> {
        self.streams_tx.values_mut().find_map(|s| {
            let kind = s.poll_keyframe_request()?;
            Some(KeyframeRequest {
                mid: s.mid(),
                rid: s.rid(),
                kind,
            })
        })
    }

    pub(crate) fn has_stream_rx(&self, ssrc: Ssrc) -> bool {
        self.streams_rx.contains_key(&ssrc)
    }

    pub(crate) fn has_stream_tx(&self, ssrc: Ssrc) -> bool {
        self.streams_tx.contains_key(&ssrc)
    }

    pub(crate) fn streams_rx(&mut self) -> impl Iterator<Item = &mut StreamRx> {
        self.streams_rx.values_mut()
    }

    pub(crate) fn streams_tx(&mut self) -> impl Iterator<Item = &mut StreamTx> {
        self.streams_tx.values_mut()
    }

    pub(crate) fn ssrcs_tx(&self, mid: Mid) -> Vec<Ssrc> {
        self.streams_tx
            .values()
            .filter(|s| s.mid() == mid)
            .map(|s| s.ssrc())
            .collect()
    }
}
