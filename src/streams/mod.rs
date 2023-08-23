use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::Duration;
use std::time::Instant;

use crate::format::CodecConfig;
use crate::media::{KeyframeRequest, Media};
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

/// Event when an encoded stream is considered paused/unpaused.
///
/// This means the stream has not received any data for some time (default 1.5 seconds).
#[derive(Debug)]
pub struct StreamPaused {
    /// The main SSRC of the encoded stream that paused.
    pub ssrc: Ssrc,

    /// The mid the encoded stream belongs to.
    pub mid: Mid,

    /// The rid, if the encoded stream has a rid.
    pub rid: Option<Rid>,

    /// Whether the stream is paused or not.
    pub paused: bool,
}

/// 255 is out of range for a real PT, which is 7 bit.
const BLANK_PACKET_DEFAULT_PT: Pt = Pt::new_with_value(255);

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

    pub(crate) fn is_pt_set(&self) -> bool {
        self.header.payload_type != BLANK_PACKET_DEFAULT_PT
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

    /// We need to report all RR/SR for a Mid together in one RTCP. This is a dynamic
    /// list that we don't want to allocate on every handle_timeout.
    mids_to_report: Vec<Mid>,
}

impl Default for Streams {
    fn default() -> Self {
        Self {
            streams_rx: Default::default(),
            streams_tx: Default::default(),
            default_ssrc_tx: 0.into(), // this will be changed
            mids_to_report: Vec::with_capacity(10),
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
            stream.maybe_reset_rtx(rtx);
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

    pub(crate) fn paused_at(&self) -> Option<Instant> {
        self.streams_rx.values().find_map(|s| s.paused_at())
    }

    pub(crate) fn timestamp_writes_at(&self) -> Option<Instant> {
        if self.streams_tx.values().any(|s| s.need_timeout()) {
            Some(already_happened())
        } else {
            None
        }
    }

    pub(crate) fn is_receiving(&self) -> bool {
        !self.streams_rx.is_empty()
    }

    pub(crate) fn handle_timeout(
        &mut self,
        now: Instant,
        sender_ssrc: Ssrc,
        do_nack: bool,
        medias: &[Media],
        config: &CodecConfig,
        feedback: &mut VecDeque<Rtcp>,
    ) {
        self.mids_to_report.clear(); // Clear for checking StreamRx.
        for stream in self.streams_rx.values() {
            if stream.need_rr(now) {
                self.mids_to_report.push(stream.mid());
            }
        }

        for stream in self.streams_rx.values_mut() {
            stream.maybe_create_keyframe_request(sender_ssrc, feedback);

            // All StreamRx belonging to the same Mid are reported together.
            if self.mids_to_report.contains(&stream.mid()) {
                stream.create_rr_and_update(now, sender_ssrc, feedback);
            }

            if do_nack {
                stream.maybe_create_nack(sender_ssrc, feedback);
            }

            stream.handle_timeout(now);
        }

        self.mids_to_report.clear(); // start over for StreamTx.
        for stream in self.streams_tx.values() {
            if stream.need_sr(now) {
                self.mids_to_report.push(stream.mid());
            }
        }

        for stream in self.streams_tx.values_mut() {
            let mid = stream.mid();

            // All StreamTx belongin to the same Mid are reported together.
            if self.mids_to_report.contains(&mid) {
                stream.create_sr_and_update(now, feedback);
            }

            // Finding the first (main) PT that also has RTX for the Media is expensive,
            // this closure is run only when needed.
            // The unwrap is okay because we cannot have StreamTx with a Mid without the corresponding Media.
            let get_media = move || (medias.iter().find(|m| m.mid() == mid).unwrap(), config);

            stream.handle_timeout(now, get_media);
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

    pub(crate) fn poll_stream_paused(&mut self) -> Option<StreamPaused> {
        self.streams_rx.values_mut().find_map(|s| s.poll_paused())
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

    pub(crate) fn remove_streams_by_mid(&mut self, mid: Mid) {
        self.streams_tx.retain(|_, s| s.mid() != mid);
        self.streams_rx.retain(|_, s| s.mid() != mid);
    }

    /// An iterator over all the tx streams for a given mid.
    pub(crate) fn streams_tx_by_mid(&mut self, mid: Mid) -> impl Iterator<Item = &mut StreamTx> {
        self.streams_tx.values_mut().filter(move |s| s.mid() == mid)
    }

    /// An iterator over all the rx streams for a given mid.
    pub(crate) fn streams_rx_by_mid(&mut self, mid: Mid) -> impl Iterator<Item = &mut StreamRx> {
        self.streams_rx.values_mut().filter(move |s| s.mid() == mid)
    }

    pub(crate) fn reset_buffers_tx(&mut self, mid: Mid) {
        for s in self.streams_tx_by_mid(mid) {
            s.reset_buffers();
        }
    }

    pub(crate) fn reset_buffers_rx(&mut self, mid: Mid) {
        for s in self.streams_rx_by_mid(mid) {
            s.reset_buffers();
        }
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
