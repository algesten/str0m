//! Media (audio/video) related content.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use crate::RtcError;
use crate::change::AddMedia;
use crate::format::CodecConfig;

use crate::packet::{CodecDepacketizer, DepacketizingBuffer, Payloader};
use crate::packet::{RedSender, RedSink, RtpMeta};
use crate::rtp_::ExtensionMap;
use crate::rtp_::MidRid;
use crate::rtp_::SRTP_BLOCK_SIZE;
use crate::rtp_::SRTP_OVERHEAD;
use str0m_proto::Id;

use crate::format::PayloadParams;
use crate::format::Vp9PacketizerMode;
use crate::sdp::Simulcast as SdpSimulcast;
use crate::sdp::{MediaLine, Msid};
use crate::streams::{RtpPacket, Streams};
use crate::util::already_happened;

mod event;
pub use event::*;

mod dtmf;
pub use dtmf::{Dtmf, TelephoneEventPayload};

mod dtmf_sender;
use dtmf_sender::{DtmfSender, DtmfTone};

mod writer;
pub use writer::Writer;

pub use crate::packet::MediaKind;
pub use crate::rtp_::{Direction, ExtensionValues, Frequency, MediaTime, Mid, Pt, Rid};

/// Mid used for SSRC 0 non-media BWE probes.
///
/// libwebrtc sends bandwidth estimation probes on SSRC 0 when:
/// - Video m-line with RTX is negotiated
/// - `allow_probe_without_media` is enabled (Chrome default)
/// - No video media packets have been sent yet
///
/// These probes carry `transport_cc` for TWCC feedback but no real media.
pub(crate) const MID_PROBE: Mid = Mid::from_array(*b"~]probe\0\0\0\0\0\0\0\0\0");

#[derive(Debug)]
/// Information about some configured media.
pub struct Media {
    // ========================================= RTP level =========================================
    //
    /// Identifier of this media.
    ///
    /// RTP level.
    mid: Mid,

    /// Canonical name.
    ///
    /// RTP level.
    cname: String,

    /// Rid that we are expecting to see on incoming RTP packets that map to this mid.
    /// Once discovered, we make an entry in `stream_rx`.
    ///
    /// RTP level.
    rids_rx: Rids,

    /// Rid that we can send using the [`Writer`].
    ///
    /// RTP level.
    rids_tx: Rids,

    // ========================================= SDP level =========================================
    //
    /// The index of this media line in the Session::media Vec.
    ///
    /// SDP property.
    index: usize,

    /// "Stream and track" identifiers.
    ///
    /// This is for _outgoing_ SDP.
    ///
    /// SDP property.
    msid: Msid,

    /// Audio or video.
    kind: MediaKind,

    /// Current media direction.
    ///
    /// Can be altered via negotiation.
    ///
    /// SDP property.
    dir: Direction,

    /// Remote PTs negotiated for this media.
    ///
    /// This tells us both the desired priority order of payload types
    /// as well as which PT the remote side wants (in case they are narrowed).
    ///
    /// These must have corresponding entries in Session::codec_config.
    ///
    /// SDP property.
    ///
    /// If this is empty, the m-line is disabled/rejected (port=0 in SDP).
    remote_pts: Vec<Pt>,

    /// Telephone events the remote peer accepts, keyed by negotiated PT.
    remote_telephone_events: HashMap<Pt, crate::format::TelephoneEvents>,

    /// Previously negotiated telephone PTs remain receivable for in-flight RTP
    /// across re-offers (RFC 3264 Section 8.3.2). Bounded by the 128 RTP PT values.
    telephone_pts_rx: Vec<Pt>,

    /// Set when this m-line has been stopped via
    /// [`SdpApi::stop_media`](crate::change::SdpApi::stop_media) or
    /// rejected by the remote peer. Independent of `remote_pts` so that
    /// an explicit stop preserves the negotiated PT list in SDP output
    /// (the SDP grammar requires at least one fmt on a port=0 m-line).
    stopped: bool,

    /// Remote extmaps negotiated for this media.
    ///
    /// The corresponding entries must exist in Session::codec_config.
    ///
    /// These are 1-indexed to be exactly like in the SDP.
    remote_exts: ExtensionMap,

    /// [`true`] if this media was created by the remote peer, [`false`] if it was created by us.
    remote_created: bool,

    /// Whether this media was declared through the Direct API.
    direct_api: bool,

    /// Simulcast configuration, if set.
    ///
    /// SDP property.
    simulcast: Option<SdpSimulcast>,

    // ========================================= Payloaders, etc =========================================
    //
    /// Buffers of incoming RTP packets. These do reordering/jitter buffer and also
    /// depayload from RTP to frames.
    depayloaders: HashMap<(Pt, Option<Rid>), DepacketizingBuffer>,

    /// Payloaders for outoing RTP packets.
    payloaders: HashMap<(Pt, Option<Rid>), PayloaderEntry>,

    /// Whether outgoing packets are wrapped in RFC 2198 RED right now. RED availability is fixed at
    /// negotiation (or set up via DirectAPI); this is the runtime send-side lever, toggled with no
    /// renegotiation. Defaults to `true`, so a negotiated RED PT wraps unless it is turned off.
    red_send_enabled: bool,

    /// Frames to payload. Should typically only be 0 or 1.
    to_payload: VecDeque<ToPayload>,

    dtmf_senders: HashMap<Option<Rid>, DtmfSender>,

    pub(crate) need_open_event: bool,
    pub(crate) need_changed_event: bool,

    /// When converting media lines to SDP, it's easier to represent the app m-line
    /// as a Media. This field is true when we do that. No Session::medias will have
    /// this set to true – they only exist temporarily.
    pub(crate) app_tmp: bool,
}

#[derive(Debug)]
/// Config value for [`Media::rids_rx()`] and [`Media::rids_tx()`]
pub enum Rids {
    /// No rid is allowed.
    None,
    /// Any Rid is allowed.
    ///
    /// This is the default value for direct API.
    Any,
    /// These specific [`Rid`] are allowed.
    ///
    /// This is the default value for Simulcast configured via SDP.
    Specific(Vec<Rid>),
}

impl Rids {
    pub(crate) fn contains(&self, rid: Rid) -> bool {
        match self {
            Rids::None => false,
            Rids::Any => true,
            Rids::Specific(v) => v.contains(&rid),
        }
    }

    pub(crate) fn is_specific(&self) -> bool {
        matches!(self, Rids::Specific(_))
    }

    fn add(&mut self, rid: Rid) {
        match self {
            Rids::None | Rids::Any => {
                *self = Rids::Specific(vec![rid]);
            }
            Rids::Specific(vec) if !vec.contains(&rid) => vec.push(rid),
            Rids::Specific(_) => {}
        }
    }
}

#[derive(Debug)]
pub(crate) struct ToPayload {
    pub pt: Pt,
    pub rid: Option<Rid>,
    pub wallclock: Instant,
    pub rtp_time: MediaTime,
    pub start_of_talk_spurt: bool,
    pub data: Arc<[u8]>,
    pub ext_vals: ExtensionValues,
}

/// Per-(pt, rid) outgoing payloader entry stored in [`Media::payloaders`]: the codec-agnostic
/// [`Payloader`] together with its optional RFC 2198 RED send state. Bundling them keeps a single
/// map keyed by (pt, rid) rather than parallel maps on the same key.
#[derive(Debug)]
struct PayloaderEntry {
    payloader: Payloader,
    red: Option<RedSender>,
}

impl Media {
    /// Identifier of the media.
    ///
    /// RTP level.
    pub fn mid(&self) -> Mid {
        self.mid
    }

    /// Canonical name.
    ///
    /// Persistent transport-level identifier for an RTP source.
    ///
    /// RTP level property. The value is sent in RTCP reports for `StreamTx`. Incoming
    /// cnames can be found in [`StreamRx::cname`][crate::rtp::StreamRx::cname].
    pub fn cname(&self) -> &str {
        &self.cname
    }

    /// Add rid as one we are expecting to receive for this mid.
    ///
    /// This is used for situations where we don't know the SSRC upfront, such as not having
    /// a=ssrc lines in an SDP. Adding a rid means we are dynamically discovering the SSRC from
    /// a mid/rid combination in the RTP header extensions.
    ///
    /// RTP level.
    pub fn expect_rid_rx(&mut self, rid: Rid) {
        self.rids_rx.add(rid);
    }

    /// Rids we are expecting to see on incoming RTP packets that map to this mid.
    ///
    /// By default this is set to [`Rids::Any`], which changes to [`Rids::Specific`] via SDP negotiation
    /// that configures Simulcast where specific rids are expected.
    ///
    /// RTP level.
    pub fn rids_rx(&self) -> &Rids {
        &self.rids_rx
    }

    /// Rids we are can send via the [`Writer`].
    ///
    /// By default this is set to [`Rids::None`], which changes to [`Rids::Specific`] via SDP negotiation
    /// that configures Simulcast where specific rids are expected.
    ///
    /// RTP level.
    pub fn rids_tx(&self) -> &Rids {
        &self.rids_tx
    }

    pub(crate) fn index(&self) -> usize {
        self.index
    }

    pub(crate) fn msid(&self) -> &Msid {
        &self.msid
    }

    /// Identifier for the group this Media belongs to.
    pub fn stream_id(&self) -> &str {
        &self.msid().stream_id
    }

    /// Identifier for this Media. Should be unique for the given stream id.
    pub fn track_id(&self) -> &str {
        &self.msid().track_id
    }

    /// Whether this media is audio or video.
    ///
    /// SDP level property.
    pub fn kind(&self) -> MediaKind {
        self.kind
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
    ///
    /// SDP level property.
    pub fn direction(&self) -> Direction {
        self.dir
    }

    /// Whether this m-line is disabled/rejected (port=0 in SDP).
    ///
    /// An m-line is disabled if it has been stopped (via
    /// [`SdpApi::stop_media`](crate::change::SdpApi::stop_media) or by the
    /// remote peer), or if no codecs matched during negotiation.
    ///
    /// SDP level property.
    pub fn disabled(&self) -> bool {
        self.stopped || self.remote_pts.is_empty()
    }

    /// Whether this m-line has been stopped.
    ///
    /// Unlike [`disabled`](Self::disabled) this does not include the "no
    /// codecs matched" case - only explicit stop via
    /// [`SdpApi::stop_media`](crate::change::SdpApi::stop_media) or a
    /// port=0 m-line received from the remote peer. A stopped m-line
    /// cannot be reactivated; its slot can however be recycled by a
    /// subsequent new m-line (RFC 8829 §5.2.2).
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    pub(crate) fn mark_stopped(&mut self) {
        self.stopped = true;
    }

    pub(crate) fn simulcast(&self) -> Option<&SdpSimulcast> {
        self.simulcast.as_ref()
    }

    pub(crate) fn poll_sample(
        &mut self,
        params: &[PayloadParams],
    ) -> Result<Option<MediaData>, RtcError> {
        for ((pt, rid), buf) in &mut self.depayloaders {
            if let Some(r) = buf.pop() {
                let dep = r.map_err(|e| RtcError::Packet(self.mid, *pt, e))?;
                let Some(codec) = params.iter().find(|c| c.pt() == *pt) else {
                    return Ok(None);
                };
                return Ok(Some(MediaData {
                    mid: self.mid,
                    pt: *pt,
                    rid: *rid,
                    params: *codec,
                    // The depacketized time is in the RTP wire clock rate. For the
                    // media (samples/frame) API we present it in the codec's nominal
                    // clock rate. These differ only for G722, which has a 16 kHz
                    // nominal rate but an 8 kHz RTP clock rate (RFC 3551 §4.5.2). For
                    // all other codecs this rebase is a no-op. See
                    // https://en.wikipedia.org/wiki/RTP_payload_formats#cite_note-55
                    time: dep.time.rebase(codec.spec().clock_rate),
                    network_time: dep.first_network_time(),
                    seq_range: dep.seq_range(),
                    contiguous: dep.contiguous,
                    ext_vals: dep.ext_vals(),
                    codec_extra: dep.codec_extra,
                    last_sender_info: dep.first_sender_info(),
                    audio_start_of_talk_spurt: codec.spec().codec.is_audio()
                        && dep.start_of_talkspurt(),
                    data: dep.data.into(),
                }));
            }
        }
        Ok(None)
    }

    pub(crate) fn depayload(
        &mut self,
        rid: Option<Rid>,
        packet: RtpPacket,
        reordering_size_audio: usize,
        reordering_size_video: usize,
        params: &[PayloadParams],
    ) {
        if !self.dir.is_receiving() {
            return;
        }

        let pt = packet.header.payload_type;

        // The session only passes packets with a configured payload type.
        let params = params.iter().find(|p| p.pt == pt).unwrap();
        let codec = params.spec.codec;

        let key = (pt, rid);

        let exists = self.depayloaders.contains_key(&key);

        if !exists {
            // How many packets to hold back in the jitter buffer.
            let hold_back = if codec.is_telephone_event() {
                // Reports are self-contained and share sequence numbers with audio.
                0
            } else if codec.is_audio() {
                reordering_size_audio
            } else {
                reordering_size_video
            };

            let mut depack: CodecDepacketizer = codec.into();

            // Enable DONL for H.265 when sprop-max-don-diff > 0 (RFC 7798 §7.1)
            if let CodecDepacketizer::H265(ref mut h265) = depack {
                if params.spec.format.sprop_max_don_diff.unwrap_or(0) > 0 {
                    h265.with_donl(true);
                }
            }

            // Enable DONL for H.266 when sprop-max-don-diff > 0 (RFC 9328 §7.2)
            if let CodecDepacketizer::H266(ref mut h266) = depack {
                if params.spec.format.sprop_max_don_diff.unwrap_or(0) > 0 {
                    h266.with_donl(true);
                }
            }

            let buffer = DepacketizingBuffer::new(depack, hold_back);

            self.depayloaders.insert((pt, rid), buffer);
        }

        let meta = RtpMeta {
            received: packet.timestamp,
            time: packet.time,
            seq_no: packet.seq_no,
            header: packet.header.clone(),
            last_sender_info: packet.last_sender_info,
        };

        for ((other_pt, other_rid), buffer) in &mut self.depayloaders {
            if *other_pt != pt && *other_rid == rid {
                buffer.push_padding(meta.clone());
            }
        }

        // The entry will be there by now.
        let buffer = self.depayloaders.get_mut(&key).unwrap();

        buffer.push(meta, packet.payload);
    }

    pub(crate) fn set_cname(&mut self, cname: String) {
        self.cname = cname;
    }

    pub(crate) fn set_msid(&mut self, msid: Msid) {
        self.msid = msid;
    }

    pub(crate) fn set_direction(&mut self, new_dir: Direction) {
        self.need_changed_event = self.dir != new_dir;
        self.dir = new_dir;
        if !new_dir.is_sending() {
            self.to_payload.clear();
            self.dtmf_senders.clear();
        }
    }

    /// Toggle RFC 2198 RED wrapping for outgoing packets. Takes effect on the next payloaded
    /// packet; RED must be available (negotiated or set via DirectAPI) for `true` to wrap.
    /// Returns whether the setting changed.
    pub(crate) fn set_red_send(&mut self, enabled: bool) -> bool {
        if self.red_send_enabled == enabled {
            return false;
        }
        self.red_send_enabled = enabled;
        true
    }

    pub(crate) fn set_simulcast(&mut self, s: SdpSimulcast) {
        debug!("Set simulcast: {:?}", s);
        self.simulcast = Some(s);
    }

    fn payloader_for(
        &mut self,
        pt: Pt,
        rid: Option<Rid>,
        params: &[PayloadParams],
        vp9_mode: Vp9PacketizerMode,
    ) -> &mut PayloaderEntry {
        self.payloaders.entry((pt, rid)).or_insert_with(|| {
            // Unwrap is OK, the pt should be checked already when calling this function.
            let params = params.iter().find(|p| p.pt == pt).unwrap();
            PayloaderEntry {
                payloader: Payloader::new(params.spec, vp9_mode),
                red: None,
            }
        })
    }

    fn set_to_payload(&mut self, to_payload: ToPayload) -> Result<(), RtcError> {
        if self.to_payload.len() > 100 {
            return Err(RtcError::WriteWithoutPoll);
        }

        self.to_payload.push_back(to_payload);

        Ok(())
    }

    fn queue_dtmf(&mut self, tone: DtmfTone) {
        self.dtmf_senders.entry(tone.rid).or_default().push(tone);
    }

    pub(crate) fn cancel_dtmf(&mut self, rid: Option<Rid>) {
        if self.dtmf_senders.remove(&rid).is_some() {
            debug!(
                "Mid ({}) cancelled DTMF for {:?} after transmit stream change",
                self.mid, rid
            );
        }
    }

    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        if !self.to_payload.is_empty() {
            Some(already_happened())
        } else {
            self.dtmf_senders
                .values()
                .filter_map(|sender| sender.poll_timeout())
                .min()
        }
    }

    pub(crate) fn do_payload(
        &mut self,
        now: Instant,
        streams: &mut Streams,
        params: &[PayloadParams],
        vp9_mode: Vp9PacketizerMode,
        mtu: usize,
        red_distances: &[u32],
    ) -> Result<(), RtcError> {
        if let Some(payload) = self.to_payload.pop_front() {
            self.payload_one(payload, streams, params, vp9_mode, mtu, red_distances)?;
        }

        let due: Vec<_> = self
            .dtmf_senders
            .iter()
            .filter(|(_, sender)| sender.poll_timeout().is_some_and(|time| time <= now))
            .map(|(rid, _)| *rid)
            .collect();
        for rid in due {
            let sender = self.dtmf_senders.get_mut(&rid).expect("sender exists");
            if let Some(packets) = sender.poll(now) {
                for payload in packets {
                    self.payload_one(payload, streams, params, vp9_mode, mtu, red_distances)?;
                }
            }
        }
        Ok(())
    }

    fn payload_one(
        &mut self,
        to_payload: ToPayload,
        streams: &mut Streams,
        params: &[PayloadParams],
        vp9_mode: Vp9PacketizerMode,
        mtu: usize,
        red_distances: &[u32],
    ) -> Result<(), RtcError> {
        let ToPayload { pt, rid, .. } = &to_payload;

        let midrid = MidRid(self.mid, *rid);

        let stream = streams.stream_tx_by_midrid(midrid);

        let Some(stream) = stream else {
            return Err(RtcError::NoSenderSource);
        };

        let pt = *pt;

        let rtp_size: usize = mtu - SRTP_OVERHEAD;
        // align to SRTP block size to minimize padding needs
        let aligned_mtu: usize = rtp_size - rtp_size % SRTP_BLOCK_SIZE;

        // The RED PT to wrap into, if RED is negotiated for this codec and send-side wrapping is
        // on. When off we send on the plain PT even though RED stays negotiated on the m-line (it
        // can be toggled back on with no renegotiation).
        let red_pt = if self.red_send_enabled {
            params.iter().find(|p| p.pt == pt).and_then(|p| p.red)
        } else {
            None
        };

        let PayloaderEntry { payloader, red } = self.payloader_for(pt, *rid, params, vp9_mode);

        let result = if let Some(red_pt) = red_pt {
            // Keep the RED sender current with the negotiated PT/pattern without discarding a live
            // talk-spurt's history. Reserve the 1-byte RED primary header so the wrapped packet
            // still fits the MTU; the sink uses the full aligned MTU as its shed budget.
            let red = red.get_or_insert_with(|| RedSender::new(red_pt, pt, red_distances));
            red.sync(red_pt, pt, red_distances);

            let packetize_mtu = aligned_mtu.saturating_sub(1);
            let mut sink = RedSink::new(stream, red, aligned_mtu);
            payloader.push_sample(to_payload, packetize_mtu, &mut sink)
        } else {
            // Drop any stale sender so its history does not persist across a RED disable.
            *red = None;
            payloader.push_sample(to_payload, aligned_mtu, stream)
        };

        result.map_err(|e| RtcError::Packet(self.mid, pt, e))
    }

    pub(crate) fn set_remote_pts(&mut self, pts: Vec<Pt>) {
        // Have we already set PTs?
        if !self.remote_pts.is_empty() {
            return;
        }

        // TODO: We should verify the remote peer doesn't suddenly change the PT
        // order or removes/adds PTs that weren't there from the start.
        debug!("Mid ({}) remote PT order is: {:?}", self.mid, pts);
        self.remote_pts = pts;
    }

    pub(crate) fn set_remote_telephone_events(
        &mut self,
        events: HashMap<Pt, crate::format::TelephoneEvents>,
        negotiated_pts: &[Pt],
    ) {
        // Telephone-event capabilities can change without stopping the media.
        // Leave ordinary codec ordering to set_remote_pts.
        self.remote_pts
            .retain(|pt| !self.remote_telephone_events.contains_key(pt) || events.contains_key(pt));
        for pt in negotiated_pts {
            if events.contains_key(pt) {
                if !self.remote_pts.contains(pt) {
                    self.remote_pts.push(*pt);
                }
                if !self.telephone_pts_rx.contains(pt) {
                    self.telephone_pts_rx.push(*pt);
                }
            }
        }
        let cancelled: usize = self
            .dtmf_senders
            .values_mut()
            .map(|sender| {
                sender.retain(|pt, event| {
                    events
                        .get(&pt)
                        .is_some_and(|supported| supported.contains(event))
                })
            })
            .sum();
        if cancelled > 0 {
            debug!(
                "Mid ({}) cancelled {} DTMF tones after renegotiation",
                self.mid, cancelled
            );
        }
        self.remote_telephone_events = events;
    }

    /// Whether the remote peer accepts an RFC 4733 event on this payload type.
    ///
    /// Use this before sending a [`TelephoneEventPayload`] via the RTP API.
    /// [`Writer::write_dtmf`] performs this check automatically.
    /// SDP negotiation supplies the remote event range; media declared through
    /// the Direct API assume events 0-16 for configured telephone-event payloads.
    /// Returns `false` if the payload type or event was not negotiated.
    pub fn supports_telephone_event(&self, pt: Pt, event: u8) -> bool {
        self.remote_telephone_events
            .get(&pt)
            .is_some_and(|events| events.contains(event))
    }

    pub(crate) fn has_telephone_event(&self, pt: Pt) -> bool {
        self.remote_telephone_events.contains_key(&pt)
    }

    pub(crate) fn receives_telephone_event(&self, pt: Pt) -> bool {
        self.telephone_pts_rx.contains(&pt)
    }

    pub(crate) fn set_remote_extmap(&mut self, exts: ExtensionMap) {
        self.remote_exts = exts;
    }

    /// The remote PT (payload types) configured for this Media.
    ///
    /// These are negotiated with the remote peer and is the order the remote prefer them.
    ///
    /// I.e. these can be fewer than the `PayloadParams` configured for the `Rtc` instance,
    /// and in a different order.
    pub fn remote_pts(&self) -> &[Pt] {
        &self.remote_pts
    }

    pub(crate) fn is_direct_api(&self) -> bool {
        self.direct_api
    }

    /// The remote, agreed on, extension map, configured for this Media.
    ///
    /// For the SDP API, these are negotiated with the remote peer.
    ///
    /// For the Direct API, these are a clone of the session configured values narrowed by media
    /// kind (audio/video).
    pub fn remote_extmap(&self) -> &ExtensionMap {
        &self.remote_exts
    }

    pub(crate) fn remote_created(&self) -> bool {
        self.remote_created
    }

    pub(crate) fn first_pt_with_rtx(&self, config: &CodecConfig) -> Option<Pt> {
        config
            .all_for_kind(self.kind)
            // Only consider negotiated PTs
            .filter(|p| self.remote_pts.contains(&p.pt))
            // Map to the first PT found in payload params with RTX
            .find_map(|p| p.resend().map(|_| p.pt))
    }

    pub(crate) fn reset_depayloader(&mut self, payload_type: Pt, rid: Option<Rid>) {
        // Simply remove the depayloader, it will be re-created on the next RTP packet.
        self.depayloaders.remove(&(payload_type, rid));
    }

    pub(crate) fn reset_depayloaders_for_rid(&mut self, rid: Option<Rid>) {
        self.depayloaders
            .retain(|(_, existing_rid), _| *existing_rid != rid);
    }

    pub(crate) fn set_rid_rx(&mut self, rids: Rids) {
        self.rids_rx = rids;
    }

    pub(crate) fn set_rid_tx(&mut self, rids: Rids) {
        let before = self.dtmf_senders.len();
        self.dtmf_senders
            .retain(|rid, _| rid.is_none_or(|rid| rids.contains(rid)));
        if self.dtmf_senders.len() != before {
            debug!(
                "Mid ({}) cancelled DTMF for withdrawn transmit RIDs",
                self.mid
            );
        }
        self.rids_tx = rids;
    }

    pub(crate) fn add_to_rid_tx(&mut self, rid: Rid) {
        self.rids_tx.add(rid)
    }
}

impl Default for Media {
    fn default() -> Self {
        Self {
            mid: Mid::new(),
            index: 0,
            app_tmp: false,
            cname: Id::<20>::random().to_string(),
            msid: Msid::random(),
            kind: MediaKind::Video,
            remote_pts: vec![],
            remote_telephone_events: HashMap::new(),
            telephone_pts_rx: vec![],
            stopped: false,
            remote_exts: ExtensionMap::empty(),
            remote_created: false,
            direct_api: false,
            dir: Direction::SendRecv,
            simulcast: None,
            rids_rx: Rids::Any,
            rids_tx: Rids::None,
            payloaders: HashMap::new(),
            depayloaders: HashMap::new(),
            to_payload: VecDeque::default(),
            dtmf_senders: HashMap::new(),
            need_open_event: true,
            need_changed_event: false,
            red_send_enabled: true,
        }
    }
}

impl Media {
    pub(crate) fn from_remote_media_line(
        l: &MediaLine,
        index: usize,
        remote_created: bool,
    ) -> Self {
        Media {
            mid: l.mid(),
            index,
            // This is not reflected back, and thus added by add_pending_changes().
            // cname,
            msid: l.msid().unwrap_or(Msid::random()),
            kind: l.typ.clone().into(),
            dir: if l.disabled {
                Direction::Inactive
            } else {
                l.direction().invert() // remote direction is reverse.
            },
            remote_created,
            ..Default::default()
        }
    }

    // Going from AddMedia to Media for pending in a Change and are sent
    // in the offer to the other side.
    //
    // from_add_media is only used when creating temporary Media to be
    // included in the SDP. We don't want to make an _actual_ changes with this.
    pub(crate) fn from_add_media(a: AddMedia) -> Self {
        Media {
            mid: a.mid,
            index: a.index,
            cname: a.cname,
            msid: a.msid,
            kind: a.kind,
            dir: a.dir,
            remote_pts: a.pts,
            remote_exts: a.exts,
            remote_created: false,
            simulcast: a.simulcast.map(|s| s.into_sdp()),
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
        kind: MediaKind,
        exts: ExtensionMap,
        remote_telephone_events: HashMap<Pt, crate::format::TelephoneEvents>,
    ) -> Media {
        let telephone_pts_rx = remote_telephone_events.keys().copied().collect();
        Media {
            mid,
            index,
            kind,
            dir: Direction::SendRecv,
            remote_telephone_events,
            telephone_pts_rx,
            remote_exts: exts,
            direct_api: true,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::format::TelephoneEvents;
    use std::time::Duration;

    #[test]
    fn withdrawing_a_rid_cancels_only_its_pending_tones() {
        let mut media = Media::default();
        let first: Rid = "first".into();
        let second: Rid = "second".into();
        let start = Instant::now();
        media.set_rid_tx(Rids::Specific(vec![first, second]));
        for (rid, offset) in [(first, 0), (second, 100)] {
            media.queue_dtmf(DtmfTone {
                pt: 126.into(),
                rid: Some(rid),
                rtp_time: MediaTime::ZERO,
                wallclock: start + Duration::from_millis(offset),
                event: 5,
                volume: 10,
                duration: Duration::from_millis(100),
                clock_rate: Frequency::EIGHT_KHZ,
                ext_vals: ExtensionValues::default(),
            });
        }
        media.set_rid_tx(Rids::Specific(vec![second]));
        assert!(!media.dtmf_senders.contains_key(&Some(first)));
        assert!(media.dtmf_senders.contains_key(&Some(second)));
        assert_eq!(
            media.poll_timeout(),
            Some(start + Duration::from_millis(120))
        );
    }

    #[test]
    fn telephone_payloads_can_be_added_and_withdrawn_during_renegotiation() {
        let mut media = Media::default();
        let narrow: Pt = 126.into();
        let wide: Pt = 121.into();
        let original = vec![0.into(), 111.into(), narrow];
        media.set_remote_pts(original.clone());
        media.set_remote_telephone_events(
            HashMap::from([(narrow, TelephoneEvents::dtmf())]),
            &original,
        );

        let added = vec![0.into(), 111.into(), narrow, wide];
        media.set_remote_pts(added.clone());
        media.set_remote_telephone_events(
            HashMap::from([
                (narrow, TelephoneEvents::dtmf()),
                (wide, TelephoneEvents::dtmf()),
            ]),
            &added,
        );
        assert_eq!(media.remote_pts(), added);

        let removed = vec![0.into(), 111.into(), wide];
        media.set_remote_pts(removed.clone());
        media.set_remote_telephone_events(
            HashMap::from([(wide, TelephoneEvents::dtmf())]),
            &removed,
        );
        assert_eq!(media.remote_pts(), removed);
        assert!(!media.has_telephone_event(narrow));
        assert!(media.has_telephone_event(wide));
        assert!(media.receives_telephone_event(narrow));
        assert!(media.receives_telephone_event(wide));
        assert!(!media.receives_telephone_event(127.into()));
    }
}
