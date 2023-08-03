use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::Duration;
use std::time::Instant;

use crate::media::KeyframeRequest;
use crate::rtp_::MediaTime;
use crate::rtp_::Pt;
use crate::rtp_::Ssrc;
use crate::rtp_::{Mid, Rid, SeqNo};
use crate::rtp_::{Rtcp, RtpHeader};
use crate::util::already_happened;

pub use self::receive::StreamRx;
pub use self::send::StreamTx;

mod receive;
mod register;
mod rtx_cache;
mod send;
mod send_queue;

pub(crate) use send::DEFAULT_RTX_CACHE_DURATION;

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

/// Packet of RTP data.
///
/// As emitted by [`Event::RtpPacket`][crate::Event::RtpPacket] when using rtp mode.
#[derive(PartialEq, Eq)]
pub struct RtpPacket {
    /// Extended sequence number to avoid having to deal with ROC.
    pub seq_no: SeqNo,

    /// Extended RTP time in the clock frequency of the codec. To avoid dealing with ROC.
    ///
    /// For a newly scheduled outgoing packet, the clock_rate is not correctly set until
    /// we do the poll_output().
    pub time: MediaTime,

    /// Parsed RTP header.
    pub header: RtpHeader,

    /// RTP payload. This contains no header.
    pub payload: Vec<u8>,

    /// str0m server timestamp.
    ///
    /// This timestamp has nothing to do with RTP itself. For outgoing packets, this is when
    /// the packet was first handed over to str0m and enqueued in the outgoing send buffers.
    /// For incoming packets it's the time we received the network packet.
    pub timestamp: Instant,

    /// Whether this packet can be nacked.
    ///
    /// This is often false for audio, but might also be false for discardable frames when
    /// using temporal encoding as in a VP8 simulcast situation.
    pub(crate) nackable: bool,
}

pub const BLANK_PACKET_DEFAULT_PT: Pt = Pt::new_with_value(0);

impl RtpPacket {
    fn blank() -> RtpPacket {
        RtpPacket {
            seq_no: 0.into(),
            time: MediaTime::new(0, 90_000),
            header: RtpHeader {
                payload_type: BLANK_PACKET_DEFAULT_PT,
                ..Default::default()
            },
            payload: vec![], // This payload is never used. See RtpHeader::create_padding_packet
            nackable: false,
            timestamp: already_happened(),
        }
    }
}

/// Holder of incoming/outgoing encoded streams.
///
/// Each encoded stream is uniquely identified by an SSRC. The concept of mid/rid sits on the Media
/// level together with the ability to translate a mid/rid to an encoded stream.
#[derive(Debug)]
pub(crate) struct Streams {
    /// All incoming encoded streams.
    streams_rx: HashMap<Ssrc, StreamRx>,

    /// All outgoing encoded streams.
    streams_tx: HashMap<Ssrc, StreamTx>,

    /// Local SSRC used before we got any StreamTx. This is used for RTCP if we don't
    /// have any reasonable value to use.
    default_ssrc_tx: Ssrc,
}

impl Default for Streams {
    fn default() -> Self {
        Self {
            streams_rx: Default::default(),
            streams_tx: Default::default(),
            default_ssrc_tx: 0.into(), // this will be changed
        }
    }
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

    pub fn remove_stream_rx(&mut self, ssrc: Ssrc) -> bool {
        self.streams_rx.remove(&ssrc).is_some()
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

    pub fn remove_stream_tx(&mut self, ssrc: Ssrc) -> bool {
        self.streams_tx.remove(&ssrc).is_some()
    }

    pub fn stream_rx(&mut self, ssrc: &Ssrc) -> Option<&mut StreamRx> {
        self.streams_rx.get_mut(ssrc)
    }

    pub fn stream_rx_by_ssrc_or_rtx(&mut self, ssrc: &Ssrc) -> Option<&mut StreamRx> {
        self.streams_rx
            .values_mut()
            .find(|s| s.ssrc() == *ssrc || s.rtx() == Some(*ssrc))
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
        do_nack: bool,
        feedback: &mut VecDeque<Rtcp>,
    ) {
        for stream in self.streams_rx.values_mut() {
            stream.maybe_create_keyframe_request(sender_ssrc, feedback);
            stream.maybe_create_rr(now, sender_ssrc, feedback);
            if do_nack {
                stream.maybe_create_nack(sender_ssrc, feedback);
            }
        }

        for stream in self.streams_tx.values_mut() {
            stream.handle_timeout(now);
            stream.maybe_create_sr(now, feedback);
        }
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

    pub(crate) fn ssrcs_tx(&self, mid: Mid) -> Vec<(Ssrc, Option<Ssrc>)> {
        self.streams_tx
            .values()
            .filter(|s| s.mid() == mid)
            .map(|s| (s.ssrc(), s.rtx()))
            .collect()
    }

    pub(crate) fn new_ssrc(&self) -> Ssrc {
        loop {
            let ssrc: Ssrc = (rand::random::<u32>()).into();

            let has_ssrc = self.has_stream_rx(ssrc) || self.has_stream_tx(ssrc);

            if has_ssrc {
                continue;
            }

            // Need to check RTX as well.
            let has_rtx_rx = self.streams_rx.values().any(|s| s.rtx() == Some(ssrc));
            if has_rtx_rx {
                continue;
            }

            let has_rtx_tx = self.streams_tx.values().any(|s| s.rtx() == Some(ssrc));
            if has_rtx_tx {
                continue;
            }

            // Not used
            break ssrc;
        }
    }

    pub fn new_ssrc_pair(&mut self) -> (Ssrc, Ssrc) {
        let ssrc = self.new_ssrc();

        let rtx = loop {
            let proposed = self.new_ssrc();
            // Avoid clashing with just allocated main SSRC.
            if proposed != ssrc {
                break proposed;
            }
        };

        (ssrc, rtx)
    }

    pub(crate) fn first_ssrc_remote(&self) -> Ssrc {
        *self.streams_rx.keys().next().unwrap_or(&0.into())
    }

    pub(crate) fn first_ssrc_local(&mut self) -> Ssrc {
        if let Some(ssrc) = self.streams_tx.keys().next() {
            // If there is some local Tx SSRC, use that.
            *ssrc
        } else {
            // Fallback in case we don't have any Tx SSRC.
            if *self.default_ssrc_tx == 0 {
                // Do not use 0, allocate one that is not in session already.
                self.default_ssrc_tx = self.new_ssrc();
            }
            self.default_ssrc_tx
        }
    }

    pub(crate) fn stream_tx_by_mid_rid(
        &mut self,
        mid: Mid,
        rid: Option<Rid>,
    ) -> Option<&mut StreamTx> {
        self.streams_tx
            .values_mut()
            .find(|s| s.mid() == mid && (rid.is_none() || s.rid() == rid))
    }

    pub(crate) fn stream_rx_by_mid_rid(
        &mut self,
        mid: Mid,
        rid: Option<Rid>,
    ) -> Option<&mut StreamRx> {
        self.streams_rx
            .values_mut()
            .find(|s| s.mid() == mid && (rid.is_none() || s.rid() == rid))
    }
}

impl fmt::Debug for RtpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtpPacket")
            .field("seq_no", &self.seq_no)
            .field("time", &self.time)
            .field("header", &self.header)
            .field("payload", &self.payload.len())
            .field("nackable", &self.nackable)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}
