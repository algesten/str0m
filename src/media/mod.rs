//! Media (audio/video) related content.

use std::collections::HashMap;
use std::time::Instant;

use crate::change::AddMedia;
use crate::io::{Id, DATAGRAM_MTU};
use crate::packet::{DepacketizingBuffer, Payloader, RtpMeta};
use crate::rtp_::SRTP_BLOCK_SIZE;
use crate::rtp_::SRTP_OVERHEAD;
use crate::RtcError;

use crate::format::PayloadParams;
use crate::sdp::Simulcast as SdpSimulcast;
use crate::sdp::{MediaLine, Msid};
use crate::streams::{RtpPacket, Streams};
use crate::util::already_happened;

mod event;
pub use event::*;

mod writer;
pub use writer::Writer;

pub use crate::packet::MediaKind;
pub use crate::rtp_::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid};

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
    rids: Rids,

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
    /// as well as which PT the remote side wants (in case they are narrowed.
    ///
    /// These must have corresponding entries in Session::codec_config.
    ///
    /// SDP property.
    remote_pts: Vec<Pt>,

    /// Simulcast configuration, if set.
    ///
    /// SDP property.
    simulcast: Option<SdpSimulcast>,

    // ========================================= Payloaders, etc =========================================
    //
    /// Buffers of incoming RTP packets. These do reordering/jitter buffer and also
    /// depayload from RTP to samples.
    depayloaders: HashMap<(Pt, Option<Rid>), DepacketizingBuffer>,

    /// Payloaders for outoing RTP packets.
    payloaders: HashMap<(Pt, Option<Rid>), Payloader>,

    /// Next sample to payload.
    to_payload: Option<ToPayload>,

    pub(crate) need_open_event: bool,
    pub(crate) need_changed_event: bool,

    /// When converting media lines to SDP, it's easier to represent the app m-line
    /// as a Media. This field is true when we do that. No Session::medias will have
    /// this set to true – they only exist temporarily.
    pub(crate) app_tmp: bool,
}

/// Config value for [`Media::rids()`]
pub enum Rids {
    /// Any Rid is allowed.
    ///
    /// This is the default value for direct API.
    Any,
    /// These specific [`Rid`] are allowed.
    ///
    /// This is the default value for Simulcast configured via SDP.
    Specific(Vec<Rid>),
}

pub(crate) struct ToPayload {
    pub pt: Pt,
    pub rid: Option<Rid>,
    pub wallclock: Instant,
    pub rtp_time: MediaTime,
    pub data: Vec<u8>,
    pub ext_vals: ExtensionValues,
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
    pub fn expect_rid(&mut self, rid: Rid) {
        if matches!(self.rids, Rids::Any) {
            self.rids = Rids::Specific(vec![]);
        }
        let Rids::Specific(v) = &mut self.rids else {
            panic!("Expected Rids::Specific");
        };
        if !v.contains(&rid) {
            v.push(rid);
        }
    }

    /// Rids we are expecting to see on incoming RTP packets that map to this mid.
    ///
    /// By default this is set to [`Rids::Any`], which changes to [`Rids::Specific`] via SDP negotiation
    /// that configures Simulcast where specific rids are expected.
    ///
    /// RTP level.
    pub fn rids(&self) -> &Rids {
        &self.rids
    }

    pub(crate) fn expects_rid(&self, rid: Rid) -> bool {
        match &self.rids {
            Rids::Any => true,
            Rids::Specific(v) => v.contains(&rid),
        }
    }

    pub(crate) fn expects_specific_rids(&self) -> bool {
        matches!(self.rids, Rids::Specific(_))
    }

    pub(crate) fn index(&self) -> usize {
        self.index
    }

    pub(crate) fn msid(&self) -> &Msid {
        &self.msid
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

    pub(crate) fn simulcast(&self) -> Option<&SdpSimulcast> {
        self.simulcast.as_ref()
    }

    pub(crate) fn poll_sample(
        &mut self,
        params: &[PayloadParams],
    ) -> Option<Result<MediaData, RtcError>> {
        for ((pt, rid), buf) in &mut self.depayloaders {
            if let Some(r) = buf.pop() {
                let codec = *params.iter().find(|c| c.pt() == *pt)?;
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

        let key = (pt, rid);

        let exists = self.depayloaders.contains_key(&key);

        if !exists {
            // This unwrap is ok because we needed the clock_rate before unpayloading.
            let params = params.iter().find(|p| p.pt == pt).unwrap();

            let codec = params.spec.codec;

            // How many packets to hold back in the jitter buffer.
            let hold_back = if codec.is_audio() {
                reordering_size_audio
            } else {
                reordering_size_video
            };

            let buffer = DepacketizingBuffer::new(codec.into(), hold_back);

            self.depayloaders.insert((pt, rid), buffer);
        }

        // The entry will be there by now.
        let buffer = self.depayloaders.get_mut(&key).unwrap();

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
        self.need_changed_event = self.dir != new_dir;
        self.dir = new_dir;
    }

    pub(crate) fn set_simulcast(&mut self, s: SdpSimulcast) {
        info!("Set simulcast: {:?}", s);
        self.simulcast = Some(s);
    }

    fn payloader_for(
        &mut self,
        pt: Pt,
        rid: Option<Rid>,
        params: &[PayloadParams],
    ) -> &mut Payloader {
        self.payloaders.entry((pt, rid)).or_insert_with(|| {
            // Unwrap is OK, the pt should be checked already when calling this function.
            let params = params.iter().find(|p| p.pt == pt).unwrap();
            Payloader::new(params.spec.codec.into())
        })
    }

    fn set_to_payload(&mut self, to_payload: ToPayload) -> Result<(), RtcError> {
        if self.to_payload.is_some() {
            return Err(RtcError::WriteWithoutPoll);
        }

        self.to_payload = Some(to_payload);

        Ok(())
    }

    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        if self.to_payload.is_some() {
            Some(already_happened())
        } else {
            None
        }
    }

    pub(crate) fn do_payload(
        &mut self,
        now: Instant,
        streams: &mut Streams,
        params: &[PayloadParams],
    ) -> Result<(), RtcError> {
        let Some(to_payload) = self.to_payload.take() else {
            return Ok(());
        };

        let ToPayload { pt, rid, .. } = &to_payload;

        let is_audio = self.kind.is_audio();

        let stream = streams.tx_by_mid_rid(self.mid, *rid);

        let Some(stream) = stream else {
            return Err(RtcError::NoSenderSource);
        };

        let pt = *pt;

        let payloader = self.payloader_for(pt, *rid, params);

        const RTP_SIZE: usize = DATAGRAM_MTU - SRTP_OVERHEAD;
        // align to SRTP block size to minimize padding needs
        const MTU: usize = RTP_SIZE - RTP_SIZE % SRTP_BLOCK_SIZE;

        payloader
            .push_sample(now, to_payload, MTU, is_audio, stream)
            .map_err(|e| RtcError::Packet(self.mid, pt, e))?;

        Ok(())
    }

    pub(crate) fn set_remote_pts(&mut self, pts: Vec<Pt>) {
        // Have we already set PTs?
        if !self.remote_pts.is_empty() {
            return;
        }

        // TODO: We should verify the remote peer doesn't suddenly change the PT
        // order or removes/adds PTs that weren't there from the start.
        info!("Mid ({}) remote PT order is: {:?}", self.mid, pts);
        self.remote_pts = pts;
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
            remote_pts: vec![],
            dir: Direction::SendRecv,
            simulcast: None,
            rids: Rids::Any,
            payloaders: HashMap::new(),
            depayloaders: HashMap::new(),
            to_payload: None,
            need_open_event: true,
            need_changed_event: false,
        }
    }
}

impl Media {
    pub(crate) fn from_remote_media_line(l: &MediaLine, index: usize) -> Self {
        Media {
            mid: l.mid(),
            index,
            // These two are not reflected back, and thus added by add_pending_changes().
            // cname,
            // msid,
            kind: l.typ.clone().into(),
            dir: l.direction().invert(), // remote direction is reverse.
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

    pub(crate) fn from_direct_api(mid: Mid, index: usize, kind: MediaKind) -> Media {
        Media {
            mid,
            index,
            kind,
            dir: Direction::SendRecv,
            ..Default::default()
        }
    }
}
