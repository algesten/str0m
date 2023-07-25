//! Media (audio/video) related content.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::change::AddMedia;
use crate::io::{Id, DATAGRAM_MTU};
use crate::packet::{DepacketizingBuffer, PacketizingBuffer, RtpMeta};
use crate::rtp_::SRTP_BLOCK_SIZE;
use crate::rtp_::{ExtensionMap, SRTP_OVERHEAD};
use crate::RtcError;

use crate::format::PayloadParams;
use crate::sdp::Simulcast as SdpSimulcast;
use crate::sdp::{MediaLine, Msid};
use crate::streams::{RtpPacket, Streams};

mod event;
pub use event::*;

mod writer;
pub use writer::Writer;

pub use crate::packet::MediaKind;
pub use crate::rtp_::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid};

/// Information about some configured media.
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

    /// Buffers of incoming RTP packets. These do reordering/jitter buffer and also
    /// depacketize from RTP to samples.
    depacketizers: HashMap<(Pt, Option<Rid>), DepacketizingBuffer>,

    /// Packetizers for outoing RTP packets.
    packetizers: HashMap<(Pt, Option<Rid>), PacketizingBuffer>,

    /// Next sample to packetize.
    to_packetize: Option<ToPacketize>,

    pub(crate) need_open_event: bool,
    pub(crate) need_changed_event: bool,

    /// When converting media lines to SDP, it's easier to represent the app m-line
    /// as a Media. This field is true when we do that. No Session::medias will have
    /// this set to true – they only exist temporarily.
    pub(crate) app_tmp: bool,
}

pub(crate) struct ToPacketize {
    pub pt: Pt,
    pub rid: Option<Rid>,
    pub wallclock: Instant,
    pub rtp_time: MediaTime,
    pub data: Vec<u8>,
    pub ext_vals: ExtensionValues,
    pub max_retain: usize, // TODO: remove this.
}

impl Media {
    /// Identifier of the media.
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub(crate) fn index(&self) -> usize {
        self.index
    }

    /// Whether this media is audio or video.
    pub fn kind(&self) -> MediaKind {
        self.kind
    }

    pub(crate) fn msid(&self) -> &Msid {
        &self.msid
    }

    pub(crate) fn cname(&self) -> &str {
        &self.cname
    }

    /// The negotiated payload parameters for this media.
    pub fn payload_params(&self) -> &[PayloadParams] {
        &self.params
    }

    /// Match the given parameters to the configured parameters for this [`Media`].
    ///
    /// In a server scenario, a certain codec configuration might not have the same
    /// payload type (PT) for two different peers. We will have incoming data with one
    /// PT and need to match that against the PT of the outgoing [`Media`].
    ///
    /// This call performs matching and if a match is found, returns the _local_ PT
    /// that can be used for sending media.
    pub fn match_params(&self, params: PayloadParams) -> Option<Pt> {
        let c = self.params.iter().max_by_key(|p| p.match_score(&params))?;
        c.match_score(&params)?; // avoid None, which isn't a match.
        Some(c.pt())
    }

    /// Current direction. This can be changed using
    /// [`SdpApi::set_direction()`][crate::SdpApi::set_direction()] followed by an SDP negotiation.
    ///
    /// To test whether it's possible to send media with the current direction, use
    ///
    /// ```no_run
    /// # use str0m::media::Media;
    /// let media: Media = todo!(); // Get hold of media row.
    /// if media.direction().is_sending() {
    ///     // media.write(...);
    /// }
    /// ```
    pub fn direction(&self) -> Direction {
        self.dir
    }

    pub(crate) fn get_params(&self, pt: Pt) -> Option<&PayloadParams> {
        self.params.iter().find(|p| p.pt == pt)
    }

    pub(crate) fn simulcast(&self) -> Option<&SdpSimulcast> {
        self.simulcast.as_ref()
    }

    pub(crate) fn poll_sample(&mut self) -> Option<Result<MediaData, RtcError>> {
        for ((pt, rid), buf) in &mut self.depacketizers {
            if let Some(r) = buf.pop() {
                let codec = *self.params.iter().find(|c| c.pt() == *pt)?;
                return Some(
                    r.map(|dep| MediaData {
                        mid: self.mid,
                        pt: *pt,
                        rid: *rid,
                        params: codec,
                        time: dep.time,
                        network_time: dep.first_network_time(),
                        seq_range: dep.seq_range(),
                        contiguous: dep.contiguous,
                        ext_vals: dep.ext_vals(),
                        codec_extra: dep.codec_extra,
                        data: dep.data,
                    })
                    .map_err(|e| RtcError::Packet(self.mid, *pt, e)),
                );
            }
        }
        None
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
        rid: Option<Rid>,
        packet: RtpPacket,
        reordering_size_audio: usize,
        reordering_size_video: usize,
    ) {
        if !self.dir.is_receiving() {
            return;
        }

        let pt = packet.header.payload_type;

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

        buffer.push(meta, packet.payload);
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

    pub(crate) fn retain_pts(&mut self, pts: &[Pt]) {
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

    /// Add rid as one we are expecting to receive for this mid.
    ///
    /// This is used for situations where we don't know the SSRC upfront, such as not having
    /// a=ssrc lines in an SDP. Adding a rid means we are dynamically discovering the SSRC from
    /// a mid/rid combination in the RTP header extensions.
    pub fn expect_rid_rx(&mut self, rid: Rid) {
        if !self.expected_rid_rx.contains(&rid) {
            self.expected_rid_rx.push(rid);
        }
    }

    pub(crate) fn expects_rid_rx(&self, rid: Rid) -> bool {
        self.expected_rid_rx.contains(&rid)
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

    fn has_pt(&self, pt: Pt) -> bool {
        self.params.iter().any(|p| p.pt == pt)
    }

    fn packetizer_for(
        &mut self,
        pt: Pt,
        rid: Option<Rid>,
        max_retain: usize,
    ) -> &mut PacketizingBuffer {
        self.packetizers.entry((pt, rid)).or_insert_with(|| {
            // Unwrap is OK, the pt should be checked already when calling this function.
            let params = self.params.iter().find(|p| p.pt == pt).unwrap();
            PacketizingBuffer::new(params.spec.codec.into(), max_retain)
        })
    }

    fn set_to_packetize(&mut self, to_packetize: ToPacketize) -> Result<(), RtcError> {
        if self.to_packetize.is_some() {
            return Err(RtcError::WriteWithoutPoll);
        }

        self.to_packetize = Some(to_packetize);

        Ok(())
    }

    pub(crate) fn do_packetize(
        &mut self,
        now: Instant,
        streams: &mut Streams,
    ) -> Result<(), RtcError> {
        let Some(to_packetize) = self.to_packetize.take() else {
            return Ok(());
        };

        let ToPacketize {
            pt,
            rid,
            max_retain,
            ..
        } = &to_packetize;

        let is_audio = self.kind.is_audio();

        let stream = streams.tx_by_mid_rid(self.mid, *rid);

        let Some(stream) = stream else {
            return Err(RtcError::NoSenderSource);
        };

        let pt = *pt;

        let packetizer = self.packetizer_for(pt, *rid, *max_retain);

        const RTP_SIZE: usize = DATAGRAM_MTU - SRTP_OVERHEAD;
        // align to SRTP block size to minimize padding needs
        const MTU: usize = RTP_SIZE - RTP_SIZE % SRTP_BLOCK_SIZE;

        packetizer
            .push_sample(now, to_packetize, MTU, is_audio, stream)
            .map_err(|e| RtcError::Packet(self.mid, pt, e))?;

        Ok(())
    }

    pub(crate) fn is_request_keyframe_possible(&self, kind: KeyframeRequestKind) -> bool {
        // TODO: It's possible to have different set of feedback enabled for different
        // payload types. I.e. we could have FIR enabled for H264, but not for VP8.
        // We might want to make this check more fine grained by testing which PT is
        // in "active use" right now.
        self.params.iter().any(|r| match kind {
            KeyframeRequestKind::Pli => r.fb_pli,
            KeyframeRequestKind::Fir => r.fb_fir,
        })
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
            packetizers: HashMap::new(),
            depacketizers: HashMap::new(),
            to_packetize: None,
            need_open_event: true,
            need_changed_event: false,
        }
    }
}

impl Media {
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
    //
    // from_add_media is only used when creating temporary Media to be
    // included in the SDP. We don't want to make an _actual_ changes with this.
    pub(crate) fn from_add_media(a: AddMedia, exts: ExtensionMap) -> Self {
        Media {
            mid: a.mid,
            index: a.index,
            cname: a.cname,
            msid: a.msid,
            kind: a.kind,
            exts,
            dir: a.dir,
            params: a.params,
            ..Default::default()
        }
    }

    pub(crate) fn from_app_tmp(mid: Mid, index: usize) -> Media {
        Media {
            mid,
            index,
            app_tmp: true,
            ..Default::default()
        }
    }

    pub(crate) fn from_direct_api(
        mid: Mid,
        index: usize,
        dir: Direction,
        exts: ExtensionMap,
        params: &[PayloadParams],
        is_audio: bool,
    ) -> Media {
        Media {
            mid,
            index,
            kind: if is_audio {
                MediaKind::Video
            } else {
                MediaKind::Audio
            },
            exts,
            dir,
            params: params.to_vec(),
            ..Default::default()
        }
    }
}
