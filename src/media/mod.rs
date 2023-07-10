use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::change::AddMedia;
use crate::io::Id;
use crate::packet::{DepacketizingBuffer, MediaKind, PacketizingBuffer, RtpMeta};
use crate::rtp::ExtensionMap;
use crate::rtp::Ssrc;
pub use crate::rtp::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid};
use crate::RtcError;

use crate::format::PayloadParams;
use crate::sdp::Simulcast as SdpSimulcast;
use crate::sdp::{MediaLine, Msid};
use crate::stats::StatsSnapshot;
use crate::streams::{StreamPacket, Streams};

mod event;
pub use event::*;

mod writer;
pub use writer::Writer;

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

    // Rid that we are expecting to see on incoming RTP packets that map to this mid.
    // Once discovered, we make an entry in `stream_rx`.
    expected_rid_rx: Vec<Rid>,

    /// Discovered incoming streams for this mid.
    ///
    /// This is deduped on Rid, if the remote side changes SSRC, we only have one entry
    /// per rid in this list.
    ///
    /// When these are set, the corresponding Streams::stream_rx should also
    /// exist. This is an internal contract we can't uphold by types, but is relied on.
    streams_rx: Vec<StreamId>,

    /// Declared outgoing streams for this mid.
    ///
    /// When these are set, the corresponding Streams::stream_tx should also
    /// exist. This is an internal contract we can't uphold by types, but is relied on.
    streams_tx: Vec<StreamId>,

    /// Buffers of incoming RTP packets. These do reordering/jitter buffer and also
    /// depacketize from RTP to samples.
    depacketizers: HashMap<(Pt, Option<Rid>), DepacketizingBuffer>,

    ///
    packetizers: HashMap<(Pt, Option<Rid>), PacketizingBuffer>,

    pub(crate) need_open_event: bool,
    pub(crate) need_changed_event: bool,

    /// When converting media lines to SDP, it's easier to represent the app m-line
    /// as a Media. This field is true when we do that. No Session::medias will have
    /// this set to true – they only exist temporarily.
    pub(crate) app_tmp: bool,
}

impl Media {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub(crate) fn index(&self) -> usize {
        self.index
    }

    pub fn kind(&self) -> MediaKind {
        self.kind
    }

    pub fn msid(&self) -> &Msid {
        &self.msid
    }

    pub fn cname(&self) -> &str {
        &self.cname
    }

    pub fn payload_params(&self) -> &[PayloadParams] {
        &self.params
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

    pub(crate) fn poll_sample(&self) -> Option<Result<MediaData, RtcError>> {
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

        let exists = self.depacketizers.contains_key(&key);

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

            self.depacketizers.insert((pt, rid), buffer);
        }

        // The entry will be there by now.
        let buffer = self.depacketizers.get_mut(&key).unwrap();

        let meta = RtpMeta {
            received: packet.timestamp,
            time: packet.time,
            seq_no: packet.seq_no,
            header: packet.header.clone(),
        };

        buffer.push(meta, packet.payload.clone());
    }

    pub(crate) fn set_cname(&mut self, cname: String) {
        self.cname = cname;
    }

    pub(crate) fn set_msid(&mut self, msid: Msid) {
        self.msid = msid;
    }

    pub(crate) fn set_direction(&mut self, new_dir: Direction) {
        self.dir = new_dir;
    }

    pub fn retain_pts(&mut self, pts: &[Pt]) {
        let mut new_pts = HashSet::new();

        for p_new in pts {
            new_pts.insert(*p_new);

            if self.params_by_pt(*p_new).is_none() {
                debug!("Ignoring new pt ({}) in mid: {}", p_new, self.mid);
            }
        }

        self.params.retain(|p| {
            let keep = new_pts.contains(&p.pt());

            if !keep {
                debug!("Mid ({}) remove pt: {}", self.mid, p.pt());
            }

            keep
        });
    }

    fn params_by_pt(&self, pt: Pt) -> Option<&PayloadParams> {
        self.params.iter().find(|p| p.pt == pt)
    }

    pub fn expect_rid_rx(&mut self, rid: Rid) {
        if !self.expected_rid_rx.contains(&rid) {
            self.expected_rid_rx.push(rid);
        }
    }

    pub(crate) fn set_exts(&mut self, exts: ExtensionMap) {
        if self.exts != exts {
            info!("Set {:?} extension map: {:?}", self.mid, exts);
            self.exts = exts;
        }
    }

    pub(crate) fn set_simulcast(&mut self, s: SdpSimulcast) {
        info!("Set simulcast: {:?}", s);
        self.simulcast = Some(s);
    }

    pub(crate) fn exts(&self) -> &ExtensionMap {
        &self.exts
    }
}

impl Default for Media {
    fn default() -> Self {
        Self {
            mid: Mid::new(),
            index: 0,
            app_tmp: false,
            cname: Id::<20>::random().to_string(),
            msid: Msid {
                stream_id: Id::<30>::random().to_string(),
                track_id: Id::<30>::random().to_string(),
            },
            kind: MediaKind::Video,
            exts: ExtensionMap::empty(),
            dir: Direction::SendRecv,
            params: vec![],
            simulcast: None,
            expected_rid_rx: vec![],
            streams_rx: vec![],
            streams_tx: vec![],
            depacketizers: HashMap::new(),
            need_open_event: true,
            need_changed_event: false,
        }
    }
}

impl Media {
    pub(crate) fn source_tx_ssrcs(&self) -> impl Iterator<Item = Ssrc> + '_ {
        self.streams_tx().iter().map(|s| s.ssrc)
    }

    pub(crate) fn from_remote_media_line(l: &MediaLine, index: usize, exts: ExtensionMap) -> Self {
        Media {
            mid: l.mid(),
            index,
            // These two are not reflected back, and thus added by add_pending_changes().
            // cname,
            // msid,
            kind: l.typ.clone().into(),
            exts,
            dir: l.direction().invert(), // remote direction is reverse.
            params: l.rtp_params(),
            ..Default::default()
        }
    }

    // Going from AddMedia to Media for pending in a Change and are sent
    // in the offer to the other side.
    pub(crate) fn from_add_media(a: AddMedia, exts: ExtensionMap) -> Self {
        let mut media = Media {
            mid: a.mid,
            index: a.index,
            cname: a.cname,
            msid: a.msid,
            kind: a.kind,
            exts,
            dir: a.dir,
            params: a.params,
            // equalize_sources: true,
            ..Default::default()
        };

        // from_add_media is only used when creating temporary Media to be
        // included in the SDP. We don't want to make an _actual_ change in the
        // Session::streams at this point, but we do want the SSRC be included
        // in the SDP.
        //
        // So whilst we typically must uphold that a Media::stream_tx/rx is
        // mapped to a real stream, this is an exception to that rule.
        for (ssrc, repairs) in a.ssrcs {
            media.streams_tx.push(StreamId {
                ssrc,
                ssrc_rtx: repairs,
                // TODO: support sending simulcast.
                rid: None,
            });
        }

        media
    }

    pub(crate) fn from_app_tmp(mid: Mid, index: usize) -> Media {
        Media {
            mid,
            index,
            app_tmp: true,
            ..Default::default()
        }
    }

    pub(crate) fn map_stream_rx(
        &mut self,
        streams: &mut Streams,
        iter: impl Iterator<Item = (Ssrc, Option<Ssrc>)>,
    ) {
        map_ids(&mut self.streams_rx, iter);
        for StreamId { ssrc, ssrc_rtx, .. } in &self.streams_rx {
            streams.expect_stream_rx(*ssrc, *ssrc_rtx);
        }
    }

    pub(crate) fn map_stream_tx(
        &mut self,
        streams: &mut Streams,
        iter: impl Iterator<Item = (Ssrc, Option<Ssrc>)>,
    ) {
        map_ids(&mut self.streams_tx, iter);
        for StreamId { ssrc, ssrc_rtx, .. } in &self.streams_rx {
            streams.declare_stream_tx(*ssrc, *ssrc_rtx);
        }
    }
}

fn map_ids(stream_ids: &mut Vec<StreamId>, iter: impl Iterator<Item = (Ssrc, Option<Ssrc>)>) {
    for (ssrc, ssrc_rtx) in iter {
        let idx = stream_ids.iter().position(|s| s.ssrc == ssrc);

        let entry = if let Some(idx) = idx {
            &mut stream_ids[idx]
        } else {
            stream_ids.push(StreamId {
                ssrc,
                ssrc_rtx,
                rid: None,
            });
            stream_ids.last_mut().unwrap()
        };

        // in case this changed
        entry.ssrc_rtx = ssrc_rtx;
    }
}
