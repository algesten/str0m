use std::collections::HashMap;
use std::time::Instant;

use crate::packet::{DepacketizingBuffer, MediaKind, RtpMeta};
use crate::rtp::ExtensionMap;
use crate::rtp::Ssrc;
pub use crate::rtp::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid};

use crate::format::PayloadParams;
use crate::sdp::Msid;
use crate::sdp::Simulcast as SdpSimulcast;
use crate::stats::StatsSnapshot;
use crate::streams::{StreamPacket, Streams};

mod event;
pub use event::*;

#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamId {
    pub ssrc: Ssrc,
    pub ssrc_rtx: Option<Ssrc>,
    pub rid: Option<Rid>,
}
impl StreamId {
    fn has_ssrc(&self, ssrc: Ssrc) -> bool {
        self.ssrc == ssrc || self.ssrc_rtx == Some(ssrc)
    }
}

pub struct Media {
    /// Three letter identifier of this media.
    mid: Mid,

    /// The index of this media line in the Session::media Vec.
    index: usize,

    /// Unique CNAME for use in Sdes RTCP packets.
    ///
    /// This is for _outgoing_ SDP. Incoming CNAME can be
    /// found in the `ssrc_info_rx`.
    cname: String,

    /// "Stream and track" identifiers.
    ///
    /// This is for _outgoing_ SDP. Incoming Msid details
    /// can be found in the `ssrc_info_rx`.
    msid: Msid,

    /// Audio or video.
    kind: MediaKind,

    /// The extensions for this media.
    exts: ExtensionMap,

    /// Current media direction.
    ///
    /// Can be altered via negotiation.
    dir: Direction,

    /// Negotiated codec parameters.
    ///
    /// The PT information from SDP.
    params: Vec<PayloadParams>,

    /// Simulcast configuration, if set.
    simulcast: Option<SdpSimulcast>,

    /// Tells whether nack is enabled for this media.
    enable_nack: bool,

    // Rid that we are expecting to see on incoming RTP packets that map to this mid.
    // Once discovered, we make an entry in `stream_rx`.
    expected_rid_rx: Vec<Rid>,

    /// Discovered incoming streams for this mid.
    ///
    /// This is deduped on Rid, if the remote side changes SSRC, we only have one entry
    /// per rid in this list.
    streams_rx: Vec<StreamId>,

    /// Declared outgoing streams for this mid.
    streams_tx: Vec<StreamId>,

    pub(crate) need_open_event: bool,
    pub(crate) need_changed_event: bool,

    /// Buffers of incoming RTP packets. These do reordering/jitter buffer and also
    /// depacketize from RTP to samples.
    buffers: HashMap<(Pt, Option<Rid>), DepacketizingBuffer>,
}

impl Media {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub fn kind(&self) -> MediaKind {
        self.kind
    }

    pub fn cname(&self) -> &str {
        &self.cname
    }

    pub(crate) fn get_params(&self, pt: Pt) -> Option<&PayloadParams> {
        self.params.iter().find(|p| p.pt == pt)
    }

    pub(crate) fn has_ssrc_rx(&self, ssrc: Ssrc) -> bool {
        self.streams_rx.iter().any(|s| s.has_ssrc(ssrc))
    }

    pub(crate) fn has_ssrc_tx(&self, ssrc: Ssrc) -> bool {
        self.streams_tx.iter().any(|s| s.ssrc == ssrc)
    }

    pub(crate) fn main_ssrc_for(&self, ssrc: Ssrc) -> Option<Ssrc> {
        let s = self.streams_rx.iter().find(|s| s.has_ssrc(ssrc))?;
        Some(s.ssrc)
    }

    pub(crate) fn map_ssrc(
        &mut self,
        ssrc: Ssrc,
        rid: Rid,
        is_repair: bool,
        streams: &mut Streams,
    ) -> Option<Ssrc> {
        if !self.expected_rid_rx.contains(&rid) {
            return None;
        }

        let has_rid = self.streams_rx.iter().any(|s| s.rid == Some(rid));

        if !has_rid {
            // We are expecting the rid, map a new entry for it.
            if is_repair {
                // We cannot map the RTX SSRC first. The main one creates the entry, then
                // we can accept the repair.
                return None;
            }

            // Create mapping in streams.
            streams.expect_stream_rx(ssrc, None);

            // Remember mapping here in Media.
            self.streams_rx.push(StreamId {
                ssrc,
                ssrc_rtx: None,
                rid: Some(rid),
            });
        }

        // At this point we definitely should have an entry for the rid.
        let s = self
            .streams_rx
            .iter_mut()
            .find(|s| s.rid == Some(rid))
            .unwrap();

        if is_repair {
            // This is the main entry, now we can accept the RTX.
            assert!(s.ssrc != ssrc);
            s.ssrc_rtx = Some(ssrc);
            streams.expect_stream_rx(s.ssrc, s.ssrc_rtx);
        }

        // Always return "main" SSRC (never RTX).
        Some(s.ssrc)
    }

    pub(crate) fn is_repair_ssrc(&self, ssrc: Ssrc) -> bool {
        let Some(s) = self.streams_rx.iter().find(|s| s.has_ssrc(ssrc)) else {
            return false;
        };
        s.ssrc_rtx == Some(ssrc)
    }

    pub(crate) fn streams_rx(&self) -> &[StreamId] {
        &self.streams_rx
    }

    pub(crate) fn streams_tx(&self) -> &[StreamId] {
        &self.streams_tx
    }

    pub(crate) fn direction(&self) -> Direction {
        self.dir
    }

    pub(crate) fn simulcast(&self) -> Option<&SdpSimulcast> {
        self.simulcast.as_ref()
    }

    pub(crate) fn visit_stats(
        &self,
        now: Instant,
        streams: &mut Streams,
        snapshot: &mut StatsSnapshot,
    ) {
        for s in &self.streams_rx {
            let Some(stream) = streams.stream_rx(&s.ssrc) else {
                continue;
            };
            let stats = stream.stats();
            // TODO here
        }
        for s in &self.streams_tx {
            let Some(stream) = streams.stream_tx(&s.ssrc) else {
                continue;
            };
            let stats = stream.stats();
            // TODO here
        }
    }

    pub(crate) fn poll_sample(&self) -> Option<Result<MediaData, crate::RtcError>> {
        todo!()
    }

    pub(crate) fn main_payload_type_for(&self, pt: Pt) -> Option<Pt> {
        let p = self
            .params
            .iter()
            .find(|p| p.pt == pt || p.resend == Some(pt))?;
        Some(p.pt)
    }

    pub(crate) fn depacketize(
        &mut self,
        packet: &StreamPacket,
        reordering_size_audio: usize,
        reordering_size_video: usize,
    ) {
        if !self.dir.is_receiving() {
            return;
        }

        let ssrc = packet.header.ssrc;
        let pt = packet.header.payload_type;
        // This unwrap is ok, because we should not call depacketize without making a
        // StreamPacket using the information in streams_rx.
        let s = self.streams_rx.iter().find(|s| s.ssrc == ssrc).unwrap();
        let rid = s.rid;
        let key = (pt, rid);

        let exists = self.buffers.contains_key(&key);

        if !exists {
            // This unwrap is ok because we needed the clock_rate before calling depacketize.
            let params = self.get_params(pt).unwrap();

            let codec = params.spec.codec;

            // How many packets to hold back in the jitter buffer.
            let hold_back = if codec.is_audio() {
                reordering_size_audio
            } else {
                reordering_size_video
            };

            let buffer = DepacketizingBuffer::new(codec.into(), hold_back);

            self.buffers.insert((pt, rid), buffer);
        }

        // The entry will be there by now.
        let buffer = self.buffers.get_mut(&key).unwrap();

        let meta = RtpMeta {
            received: packet.timestamp,
            time: packet.time,
            seq_no: packet.seq_no,
            header: packet.header.clone(),
        };

        buffer.push(meta, packet.payload.clone());
    }
}
