//! Media (audio/video) related content.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use net_::{Id, DATAGRAM_MTU};
use packet::{DepacketizingBuffer, Packetized, PacketizingBuffer};
use rtp::{Extensions, Fir, FirEntry, NackEntry, Pli, Rtcp};
use rtp::{RtcpFb, RtpHeader, SdesType, VideoOrientation};
use rtp::{SeqNo, SRTP_BLOCK_SIZE, SRTP_OVERHEAD};

pub use packet::RtpMeta;
pub use rtp::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid, Ssrc};
pub use sdp::{Codec, FormatParams};

use sdp::{MediaLine, MediaType, Msid, Simulcast as SdpSimulcast};

mod codec;
pub use codec::{CodecConfig, PayloadParams};

mod app;
pub(crate) use app::App;

mod receiver;
use receiver::ReceiverSource;

mod sender;
use sender::SenderSource;

mod register;

use crate::change::AddMedia;
use crate::stats::StatsSnapshot;
use crate::util::already_happened;
use crate::RtcError;

// How often we remove unused senders/receivers.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

/// A new media m-line appeared in an SDP negotation.
///
/// This event fires both for negotations triggered by a remote or local offer.
///
/// Does not fire for application m-lines (data channel).
#[derive(Debug, PartialEq, Eq)]
pub struct MediaAdded {
    /// Identifier of the new m-line.
    pub mid: Mid,

    /// The kind of media the m-line will carry.
    pub kind: MediaKind,

    /// Current direction of the m-line.
    pub direction: Direction,

    /// If simulcast is configured, this holds the Rids.
    ///
    /// `a=simulcast:send h;l`
    pub simulcast: Option<Simulcast>,
}

/// A change happening during an SDP re-negotation.
///
/// This event fires both for re-negotations triggered by a remote or local offer.
///
/// Does not fire for application m-lines (data channel).
#[derive(Debug, PartialEq, Eq)]
pub struct MediaChanged {
    /// Identifier of the new m-line.
    pub mid: Mid,

    /// Current direction of the m-line.
    pub direction: Direction,
}

/// Simplified information about the simulcast config from SDP.
///
/// The [full spec][1] covers many cases that are not used by simple simulcast.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-sdp-simulcast-14
#[derive(Debug, PartialEq, Eq)]
pub struct Simulcast {
    pub send: Vec<Rid>,
    pub recv: Vec<Rid>,
}

/// Video or audio data from the remote peer.
///
/// This is obtained via [`Event::MediaData`][crate::Event::MediaData].
#[derive(PartialEq, Eq)]
pub struct MediaData {
    /// Identifier of the m-line in the SDP this media belongs to.
    pub mid: Mid,

    /// Payload type (PT) tells which negotiated codec is being used. An m-line
    /// can carry different codecs, the payload type can theoretically change
    /// from one packet to the next.
    pub pt: Pt,

    /// Rtp Stream Id (RID) identifies an RTP stream without refering to its
    /// Synchronization Source (SSRC).
    ///
    /// This is a newer standard that is sometimes used in WebRTC to identify
    /// a stream. Specifically when using Simulcast in Chrome.
    pub rid: Option<Rid>,

    /// Parameters for the codec. This is used to match incoming PT to ougoing PT.
    pub params: PayloadParams,

    /// The RTP media time of this packet. Media time is described as a nominator/denominator
    /// quantity. The nominator is the timestamp field from the RTP header, the denominator
    /// depends on whether this is an audio or video packet.
    ///
    /// For audio the timebase is 48kHz for video it is 90kHz.
    pub time: MediaTime,

    /// Whether the data is contiguous from the one just previously emitted. If this is false,
    /// we got an interruption in RTP packets, and the data may or may not be usable in a decoder
    /// without requesting a new keyframe.
    ///
    /// For audio this flag most likely doesn't matter.
    pub contiguous: bool,

    /// The actual packet data a.k.a Sample.
    ///
    /// Bigger samples don't fit in one UDP packet, thus WebRTC RTP is chopping up codec
    /// transmission units into smaller parts.
    ///
    /// This data is a full depacketized Sample.
    pub data: Vec<u8>,

    /// RTP header extensions for this media data. This is taken from the
    /// first RTP header.
    pub ext_vals: ExtensionValues,

    /// The individual packet metadata that were part of making the Sample in `data`.
    pub meta: Vec<RtpMeta>,
}

/// Details for an incoming a keyframe request (PLI or FIR).
///
/// This is obtained via the [`Event::KeyframeRequest`][crate::Event::KeyframeRequest].
///
/// Sending a keyframe request is done via [`Media::request_keyframe()`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyframeRequest {
    /// The media identifier this keyframe request is for.
    pub mid: Mid,

    /// Rid the keyframe request is for. Relevant when doing simulcast.
    pub rid: Option<Rid>,

    /// The kind of keyframe request (PLI or FIR).
    pub kind: KeyframeRequestKind,
}

/// Type of keyframe request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyframeRequestKind {
    /// Picture Loss Indiciation (PLI) is a less severe keyframe request that can be
    /// automatically generated by an SFU or by the end peer.
    Pli,

    /// Full Intra Request (PLI) is a more severe keyframe request that should only
    /// be used when it's impossible for an end peer to show a video stream.
    Fir,
}
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

pub(crate) trait Source {
    fn ssrc(&self) -> Ssrc;
    fn rid(&self) -> Option<Rid>;
    #[must_use]
    fn set_rid(&mut self, rid: Rid) -> bool;
    fn is_rtx(&self) -> bool;
    fn repairs(&self) -> Option<Ssrc>;
    #[must_use]
    fn set_repairs(&mut self, ssrc: Ssrc) -> bool;
}

/// Audio or video media. An m-line in the SDP.
///
/// Instances of [`Media`] are obtained via [`Rtc::media()`][crate::Rtc::media()]. The instance
/// only exists for m-lines that have passed the offer/answer SDP negotiation.
///
/// This is mainly a handle to send outgoing media, but also contains information about the media.
///
/// ```no_run
/// # use str0m::{Rtc, media::Mid};
///
/// let mut rtc = Rtc::new();
///
/// // add candidates, do SDP negotation
/// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
///
/// let media = rtc.media(mid).unwrap();
/// ```
#[derive(Debug)]
pub struct Media {
    /// Three letter identifier of this m-line.
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

    /// Audio eller video.
    kind: MediaKind,

    /// The extenions for this m-line.
    exts: Extensions,

    /// Current media direction.
    ///
    /// Can be altered via negotiation.
    dir: Direction,

    /// Negotiated codec parameters.
    ///
    /// The PT information from SDP.
    params: Vec<PayloadParams>,

    /// Receiving sources (SSRC).
    ///
    /// These are created first time we observe the SSRC in an incoming RTP packet.
    /// Each source keeps track of packet loss, nack, reports etc. Receiving sources are
    /// cleaned up when we haven't received any data for the SSRC for a while.
    sources_rx: Vec<ReceiverSource>,

    /// Sender sources (SSRC).
    ///
    /// Created when we configure new m-lines via Changes API.
    sources_tx: Vec<SenderSource>,

    /// Last time we ran cleanup.
    last_cleanup: Instant,

    /// Last time we produced regular feedback (SR/RR).
    last_regular_feedback: Instant,

    /// Buffers for incoming data.
    ///
    /// Video samples are often fragmented over several RTP packets. These buffers reassembles
    /// the incoming RTP to full samples.
    buffers_rx: HashMap<(Pt, Option<Rid>), DepacketizingBuffer>,

    /// Buffers for outgoing data.
    ///
    /// When writing a sample we create a number of RTP packets to send. These buffers have the
    /// individual RTP data payload ready to send.
    buffers_tx: HashMap<Pt, PacketizingBuffer>,

    /// Queued resends.
    ///
    /// These have been scheduled via nacks.
    resends: VecDeque<Resend>,

    /// Whether the media line needs to be advertised in an event.
    pub(crate) need_open_event: bool,

    // Whether the media line needs to be notified of a change with an event.
    pub(crate) need_changed_event: bool,

    /// If we receive an rtcp request for a keyframe, this holds what kind.
    keyframe_request_rx: Option<(Option<Rid>, KeyframeRequestKind)>,

    /// If we are to send an rtcp request for a keyframe, this holds what kind.
    keyframe_request_tx: Option<(Ssrc, KeyframeRequestKind)>,

    /// Simulcast configuration, if set.
    simulcast: Option<SdpSimulcast>,

    /// Sources are kept in "mirrored pairs", i.e. if we have a ReceiverSource
    /// with Ssrc A and Rid B, there should be an equivalent SenderSource with Ssrc C and Rid B.
    equalize_sources: bool,

    /// Upon SDP negotiation set whether nack is enabled for this m-line.
    enable_nack: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Types of media.
pub enum MediaKind {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
}

struct NextPacket<'a> {
    pt: Pt,
    pkt: &'a Packetized,
    ssrc: Ssrc,
    seq_no: SeqNo,
    orig_seq_no: Option<SeqNo>,
}

impl Media {
    /// Identifier of the m-line.
    pub fn mid(&self) -> Mid {
        self.mid
    }

    /// The index of the line in the SDP. Once negotiated this cannot change.
    pub fn index(&self) -> usize {
        self.index
    }

    pub(crate) fn cname(&self) -> &str {
        &self.cname
    }

    pub(crate) fn set_cname(&mut self, cname: String) {
        self.cname = cname;
    }

    pub(crate) fn msid(&self) -> &Msid {
        &self.msid
    }

    pub(crate) fn set_msid(&mut self, msid: Msid) {
        self.msid = msid;
    }

    pub(crate) fn kind(&self) -> MediaKind {
        self.kind
    }

    pub(crate) fn set_exts(&mut self, exts: Extensions) {
        if self.exts != exts {
            info!("Set {:?} extensions: {:?}", self.mid, exts);
            self.exts = exts;
        }
    }

    pub(crate) fn exts(&self) -> &Extensions {
        &self.exts
    }

    /// Current direction. This can be changed using
    /// [`ChangeSet::set_direction()`][crate::ChangeSet::set_direction()] followed by an SDP negotiation.
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

    fn codec_by_pt(&self, pt: Pt) -> Option<&PayloadParams> {
        self.params.iter().find(|c| c.pt() == pt)
    }

    /// The negotiated payload parameters for this m-line.
    pub fn payload_params(&self) -> &[PayloadParams] {
        &self.params
    }

    /// Match the given parameters to the configured parameters for this [`Media`].
    ///
    /// In a server scenario, a certain codec configuration might not have the same
    /// payload type (PT) for two different peers. We will have incoming data with one
    /// PT and need to match that against the PT of the outgoing `Media`/m-line.
    ///
    /// This call performs matching and if a match is found, returns the _local_ PT
    /// that can be used for sending media.
    pub fn match_params(&self, params: PayloadParams) -> Option<Pt> {
        let c = self
            .params
            .iter()
            .max_by_key(|p| p.match_score(params.inner()))?;
        c.match_score(params.inner())?; // avoid None, which isn't a match.
        Some(c.pt())
    }

    /// Send outgoing media data via this m-line.
    ///
    /// The `pt` is the payload type for sending and must match the codec of the media data.
    /// This is typically done using [`Media::match_params()`] to compare an incoming set of
    /// parameters with the configured ones in this `Media` instance. It's also possible to
    /// manually match the codec using [`Media::payload_params()`].
    ///
    /// `rid` is [Rtp Stream Identifier][1]. In classic RTP, individual RTP packets are identified
    /// via an RTP header value `SSRC` (Synchronization Source). However it's been proposed to send
    /// the RID in a header extension as an alternative way, making SSRC less important. Currently
    /// this is only used in Chrome when doing Simulcast.
    ///
    /// This operation fails if the current [`Media::direction()`] does not allow sending, the
    /// PT doesn't match a negotiated codec, or the RID (`None` or a value) does not match
    /// anything negotiated.
    ///
    /// ```no_run
    /// # use str0m::{Rtc};
    /// # use str0m::media::{PayloadParams, MediaData, Mid};
    /// let mut rtc = Rtc::new();
    ///
    /// // add candidates, do SDP negotation
    /// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
    ///
    /// let media = rtc.media(mid).unwrap();
    ///
    /// // Get incoming media data from another peer
    /// let data: MediaData = todo!();
    ///
    /// // Match incoming PT to an outgoing PT.
    /// let pt = media.match_params(data.params).unwrap();
    ///
    /// media.writer(pt).write(data.time, &data.data).unwrap();
    /// ```
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc8852
    pub fn writer(&mut self, pt: Pt) -> Writer<'_> {
        Writer {
            media: self,
            pt,
            rid: None,
            ext_vals: ExtensionValues::default(),
        }
    }

    /// Write to the packetizer.
    fn write(
        &mut self,
        pt: Pt,
        ts: MediaTime,
        data: &[u8],
        rid: Option<Rid>,
        ext_vals: ExtensionValues,
    ) -> Result<usize, RtcError> {
        if !self.dir.is_sending() {
            return Err(RtcError::NotSendingDirection(self.dir));
        }

        let codec = { self.codec_by_pt(pt).map(|p| p.codec()) };

        let codec = match codec {
            Some(v) => v,
            None => return Err(RtcError::UnknownPt(pt)),
        };

        // The SSRC is figured out given the simulcast level.
        let tx = get_source_tx(&mut self.sources_tx, rid, false).ok_or(RtcError::NoSenderSource)?;

        let ssrc = tx.ssrc();

        let buf = self.buffers_tx.entry(pt).or_insert_with(|| {
            let max_retain = if codec.is_audio() { 4096 } else { 2048 };
            PacketizingBuffer::new(codec.into(), max_retain)
        });

        trace!("Write to packetizer time: {:?} bytes: {}", ts, data.len());
        const MTU: usize = DATAGRAM_MTU - SRTP_OVERHEAD;
        if let Err(e) = buf.push_sample(ts, data, ssrc, rid, ext_vals, MTU) {
            return Err(RtcError::Packet(self.mid, pt, e));
        };

        Ok(buf.free())
    }

    /// Test if the kind of keyframe request is possible.
    ///
    /// Sending a keyframe request requires the mechanic to be negotiated as a feedback mechanic
    /// in the SDP offer/answer dance first.
    ///
    /// Specifically these SDP lines would enable FIR and PLI respectively (for payload type 96).
    ///
    /// ```text
    /// a=rtcp-fb:96 ccm fir
    /// a=rtcp-fb:96 nack pli
    /// ```
    pub fn is_request_keyframe_possible(&self, kind: KeyframeRequestKind) -> bool {
        // TODO: It's possible to have different set of feedback enabled for different
        // payload types. I.e. we could have FIR enabled for H264, but not for VP8.
        // We might want to make this check more fine grained by testing which PT is
        // in "active use" right now.
        self.params.iter().any(|r| match kind {
            KeyframeRequestKind::Pli => r.inner().fb_pli,
            KeyframeRequestKind::Fir => r.inner().fb_fir,
        })
    }

    /// Request a keyframe from a remote peer sending media data.
    ///
    /// This can fail if the kind of request (PLI or FIR), as specified by the
    /// [`KeyframeRequestKind`], is not negotiated in the SDP answer/offer for
    /// this m-line.
    ///
    /// To ensure the call will not fail, use [`Media::is_request_keyframe_possible()`] to
    /// check whether the feedback mechanism is enabled.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use str0m::{Rtc};
    /// # use str0m::media::{Mid, KeyframeRequestKind};
    /// let mut rtc = Rtc::new();
    ///
    /// // add candidates, do SDP negotation
    /// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
    ///
    /// let media = rtc.media(mid).unwrap();
    ///
    /// media.request_keyframe(None, KeyframeRequestKind::Pli).unwrap();
    /// ```
    pub fn request_keyframe(
        &mut self,
        rid: Option<Rid>,
        kind: KeyframeRequestKind,
    ) -> Result<(), RtcError> {
        if !self.is_request_keyframe_possible(kind) {
            return Err(RtcError::FeedbackNotEnabled(kind));
        }

        let rx = self
            .sources_rx
            .iter()
            .find(|s| s.rid() == rid && !s.is_rtx())
            .ok_or(RtcError::NoReceiverSource(rid))?;

        if let Some(rid) = rid {
            info!(
                "Request keyframe ({:?}, {:?}) SSRC: {}",
                kind,
                rid,
                rx.ssrc()
            );
        } else {
            info!("Request keyframe ({:?}) SSRC: {}", kind, rx.ssrc());
        }
        self.keyframe_request_tx = Some((rx.ssrc(), kind));

        Ok(())
    }

    pub(crate) fn poll_packet(
        &mut self,
        now: Instant,
        exts: &Extensions,
        twcc: &mut u64,
        buf: &mut Vec<u8>,
    ) -> Option<(RtpHeader, SeqNo)> {
        let mid = self.mid;

        let next = if let Some(next) = self.poll_packet_resend(now) {
            next
        } else if let Some(next) = self.poll_packet_regular(now) {
            next
        } else {
            return None;
        };

        let mut header = RtpHeader {
            payload_type: next.pt,
            sequence_number: *next.seq_no as u16,
            timestamp: next.pkt.ts.numer() as u32,
            ssrc: next.ssrc,
            ext_vals: next.pkt.exts,
            ..Default::default()
        };
        // ::new(next.pt, next.seq_no, next.pkt.ts, next.ssrc);
        header.marker = next.pkt.last;

        // We can fill out as many values we want here, only the negotiated ones will
        // be used when writing the RTP packet.
        //
        // These need to match `Extension::is_supported()` so we are sending what we are
        // declaring we support.
        header.ext_vals.abs_send_time = Some(now.into());
        header.ext_vals.mid = Some(mid);
        header.ext_vals.transport_cc = Some(*twcc as u16);
        *twcc += 1;

        buf.resize(2000, 0);
        let header_len = header.write_to(buf, exts);
        assert!(header_len % 4 == 0, "RTP header must be multiple of 4");
        header.header_len = header_len;

        let mut body_out = &mut buf[header_len..];

        // For resends, the original seq_no is inserted before the payload.
        if let Some(orig_seq_no) = next.orig_seq_no {
            let n = RtpHeader::write_original_sequence_number(body_out, orig_seq_no);
            body_out = &mut body_out[n..];
        }

        let body_len = next.pkt.data.len();
        body_out[..body_len].copy_from_slice(&next.pkt.data);

        // pad for SRTP
        let pad_len = RtpHeader::pad_packet(&mut buf[..], header_len, body_len, SRTP_BLOCK_SIZE);

        buf.truncate(header_len + body_len + pad_len);

        Some((header, next.seq_no))
    }

    fn poll_packet_resend(&mut self, now: Instant) -> Option<NextPacket<'_>> {
        loop {
            let resend = self.resends.pop_front()?;

            // If there is no buffer for this resend, we skip to next. This is
            // a weird situation though, since it means the other side sent a nack for
            // an SSRC that matched this Media, but didnt match a buffer_tx.
            let buffer = match self.buffers_tx.values().find(|p| p.has_ssrc(resend.ssrc)) {
                Some(v) => v,
                None => continue,
            };

            // The seq_no could simply be too old to exist in the buffer, in which
            // case we will not do a resend.
            let pkt = match buffer.get(resend.seq_no) {
                Some(v) => v,
                None => continue,
            };

            // The send source, to get a contiguous seq_no for the resend.
            // Audio should not be resent, so this also gates whether we are doing resends at all.
            let source = match get_source_tx(&mut self.sources_tx, pkt.rid, true) {
                Some(v) => v,
                None => continue,
            };

            source.update_sent_bytes(pkt.data.len() as u64, true);

            let seq_no = source.next_seq_no(now);

            // The resend ssrc. This would correspond to the RTX PT for video.
            let ssrc_rtx = source.ssrc();

            let orig_seq_no = Some(resend.seq_no);

            // Check that our internal state of organizing SSRC for senders is correct.
            assert_eq!(pkt.ssrc, resend.ssrc);
            assert_eq!(source.repairs(), Some(resend.ssrc));

            return Some(NextPacket {
                pt: resend.pt,
                pkt,
                ssrc: ssrc_rtx,
                seq_no,
                orig_seq_no,
            });
        }
    }

    fn poll_packet_regular(&mut self, now: Instant) -> Option<NextPacket<'_>> {
        // exit via ? here is ok since that means there is nothing to send.
        let (pt, pkt) = next_send_buffer(&mut self.buffers_tx)?;

        let source = self
            .sources_tx
            .iter_mut()
            .find(|s| s.ssrc() == pkt.ssrc)
            .expect("SenderSource for packetized write");

        source.update_sent_bytes(pkt.data.len() as u64, false);

        let seq_no = source.next_seq_no(now);
        pkt.seq_no = Some(seq_no);

        Some(NextPacket {
            pt,
            pkt,
            ssrc: pkt.ssrc,
            seq_no,
            orig_seq_no: None,
        })
    }
    pub(crate) fn get_or_create_source_rx(&mut self, ssrc: Ssrc) -> &mut ReceiverSource {
        let maybe_idx = self.sources_rx.iter().position(|r| r.ssrc() == ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_rx[idx]
        } else {
            self.equalize_sources = true;
            self.sources_rx.push(ReceiverSource::new(ssrc));
            self.sources_rx.last_mut().unwrap()
        }
    }

    pub(crate) fn get_or_create_source_tx(&mut self, ssrc: Ssrc) -> &mut SenderSource {
        let maybe_idx = self.sources_tx.iter().position(|r| r.ssrc() == ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_tx[idx]
        } else {
            self.equalize_sources = true;
            self.sources_tx.push(SenderSource::new(ssrc));
            self.sources_tx.last_mut().unwrap()
        }
    }

    pub(crate) fn set_equalize_sources(&mut self) {
        self.equalize_sources = true;
    }

    pub(crate) fn equalize_sources(&self) -> bool {
        self.equalize_sources
    }

    pub(crate) fn do_equalize_sources(&mut self, new_ssrc: &mut impl Iterator<Item = Ssrc>) {
        while self.sources_rx.len() < self.sources_tx.len() {
            let ssrc = new_ssrc.next().unwrap();
            self.get_or_create_source_rx(ssrc);
        }
        while self.sources_tx.len() < self.sources_rx.len() {
            let ssrc = new_ssrc.next().unwrap();
            self.get_or_create_source_tx(ssrc);
        }

        // Now there should be equal amount of receivers/senders.

        let mut txs: Vec<_> = self
            .sources_tx
            .iter_mut()
            .map(|t| t as &mut dyn Source)
            .collect();

        let mut rxs: Vec<_> = self
            .sources_rx
            .iter_mut()
            .map(|t| t as &mut dyn Source)
            .collect();

        fn equalize(from: &[&mut dyn Source], to: &mut [&mut dyn Source]) {
            for i in 0..from.len() {
                let rx = &from[i];
                if let Some(rid) = rx.rid() {
                    let _ = to[i].set_rid(rid);
                }
                if let Some(repairs) = rx.repairs() {
                    let j = from.iter().position(|s| s.ssrc() == repairs);
                    if let Some(j) = j {
                        let ssrc_tx = to[j].ssrc();
                        let _ = to[i].set_repairs(ssrc_tx);
                    }
                }
            }
        }

        // Now propagated rid/repairs both ways, but let rxs be dominant, so do rx -> tx first.
        equalize(&rxs, &mut txs);
        equalize(&txs, &mut rxs);

        self.equalize_sources = false;
    }

    pub(crate) fn get_params(&self, header: &RtpHeader) -> Option<&PayloadParams> {
        let pt = header.payload_type;
        self.params
            .iter()
            .find(|p| p.inner().codec.pt == pt || p.inner().resend == Some(pt))
    }

    pub(crate) fn has_nack(&mut self) -> bool {
        if !self.enable_nack {
            return false;
        }
        self.sources_rx
            .iter_mut()
            .filter(|s| !s.is_rtx())
            .any(|s| s.has_nack())
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        // TODO(martin): more cleanup
        self.last_cleanup = now;
    }

    pub(crate) fn poll_timeout(&mut self) -> Option<Instant> {
        Some(self.cleanup_at())
    }

    fn cleanup_at(&self) -> Instant {
        self.last_cleanup + CLEANUP_INTERVAL
    }

    pub(crate) fn source_tx_ssrcs(&self) -> impl Iterator<Item = Ssrc> + '_ {
        self.sources_tx.iter().map(|s| s.ssrc())
    }

    pub(crate) fn maybe_create_keyframe_request(
        &mut self,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) {
        let Some((ssrc, kind)) = self.keyframe_request_tx.take() else {
            return;
        };

        match kind {
            KeyframeRequestKind::Pli => feedback.push_back(Rtcp::Pli(Pli { sender_ssrc, ssrc })),
            KeyframeRequestKind::Fir => {
                // Unwrap is ok, because MediaWriter ensures the ReceiverSource exists.
                let rx = self
                    .sources_rx
                    .iter_mut()
                    .find(|s| s.ssrc() == ssrc)
                    .unwrap();

                feedback.push_back(Rtcp::Fir(Fir {
                    sender_ssrc,
                    reports: FirEntry {
                        ssrc,
                        seq_no: rx.next_fir_seq_no(),
                    }
                    .into(),
                }));
            }
        }
    }

    /// Creates sender info and receiver reports for all senders/receivers
    pub(crate) fn maybe_create_regular_feedback(
        &mut self,
        now: Instant,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) -> Option<()> {
        if now < self.regular_feedback_at() {
            return None;
        }

        // Since we're making new sender/receiver reports, clear out previous.
        feedback.retain(|r| !matches!(r, Rtcp::SenderReport(_) | Rtcp::ReceiverReport(_)));

        if self.dir.is_sending() {
            for s in &mut self.sources_tx {
                let sr = s.create_sender_report(now);
                let ds = s.create_sdes(&self.cname);

                debug!("Created feedback SR: {:?}", sr);
                feedback.push_back(Rtcp::SenderReport(sr));
                feedback.push_back(Rtcp::SourceDescription(ds));
            }
        }

        if self.dir.is_receiving() {
            for s in &mut self.sources_rx {
                let mut rr = s.create_receiver_report(now);
                rr.sender_ssrc = sender_ssrc;

                debug!("Created feedback RR: {:?}", rr);
                feedback.push_back(Rtcp::ReceiverReport(rr));
            }
        }

        // Update timestamp to move time when next is created.
        self.last_regular_feedback = now;

        Some(())
    }

    /// Creates nack reports for receivers, if needed.
    pub(crate) fn create_nack(&mut self, sender_ssrc: Ssrc, feedback: &mut VecDeque<Rtcp>) {
        if !self.enable_nack {
            return;
        }
        for s in &mut self.sources_rx {
            if s.is_rtx() {
                continue;
            }
            if let Some(mut nack) = s.create_nack() {
                nack.sender_ssrc = sender_ssrc;
                debug!("Created feedback NACK: {:?}", nack);
                feedback.push_back(Rtcp::Nack(nack));
            }
        }
    }

    /// Appply incoming RTCP feedback.
    pub(crate) fn handle_rtcp_fb(&mut self, now: Instant, fb: RtcpFb) -> Option<()> {
        debug!("Handle RTCP feedback: {:?}", fb);

        if fb.is_for_rx() {
            self.handle_rtcp_fb_rx(now, fb)?;
        } else {
            self.handle_rtcp_fb_tx(now, fb)?;
        }

        Some(())
    }

    pub(crate) fn handle_rtcp_fb_rx(&mut self, now: Instant, fb: RtcpFb) -> Option<()> {
        let ssrc = fb.ssrc();

        let source_rx = self.sources_rx.iter_mut().find(|s| s.ssrc() == ssrc)?;

        use RtcpFb::*;
        match fb {
            SenderInfo(v) => {
                source_rx.set_sender_info(now, v);
            }
            SourceDescription(v) => {
                for (sdes, st) in v.values {
                    if sdes == SdesType::CNAME {
                        if st.is_empty() {
                            // In simulcast, chrome doesn't send the SSRC lines, but
                            // expects us to infer that from rtp headers. It does
                            // however send the SourceDescription RTCP with an empty
                            // string CNAME. ¯\_(ツ)_/¯
                            return None;
                        }

                        // Here we _could_ check CNAME here matches something. But
                        // CNAMEs are a bit unfashionable with the WebRTC spec people.
                        return None;
                    }
                }
            }
            Goodbye(_v) => {
                // For some reason, Chrome sends a Goodbye on every SDP negotation for all active
                // m-lines. Seems strange, but lets not reset any state.
                // self.sources_rx.retain(|s| {
                //     let remove = s.ssrc() == v || s.repairs() == Some(v);
                //     if remove {
                //         trace!("Remove ReceiverSource on Goodbye: {:?}", s.ssrc());
                //     }
                //     !remove
                // });
            }
            _ => {}
        }

        Some(())
    }

    pub(crate) fn handle_rtcp_fb_tx(&mut self, _now: Instant, fb: RtcpFb) -> Option<()> {
        let ssrc = fb.ssrc();

        let source_tx = self.sources_tx.iter_mut().find(|s| s.ssrc() == ssrc)?;

        use RtcpFb::*;
        match fb {
            ReceptionReport(v) => {
                // TODO: What to do with these?
                trace!("Handle reception report: {:?}", v);
            }
            Nack(ssrc, list) => {
                let entries = list.into_iter();
                self.handle_nack(ssrc, entries)?;
            }
            Pli(_) => self.keyframe_request_rx = Some((source_tx.rid(), KeyframeRequestKind::Pli)),
            Fir(_) => self.keyframe_request_rx = Some((source_tx.rid(), KeyframeRequestKind::Fir)),
            Twcc(_) => unreachable!("TWCC should be handled on session level"),
            _ => {}
        }

        Some(())
    }

    pub(crate) fn apply_changes(
        &mut self,
        m: &MediaLine,
        config: &CodecConfig,
        session_exts: &Extensions,
    ) {
        // Nack enabled
        {
            let enabled = m.rtp_params().iter().any(|p| p.fb_nack);
            if enabled && !self.enable_nack {
                debug!("Enable NACK feedback ({:?})", self.mid);
                self.enable_nack = true;
            }
        }

        // Directional changes
        {
            // All changes come from the other side, either via an incoming OFFER
            // or a ANSWER from our OFFER. Either way, the direction is inverted to
            // how we have it locally.
            let new_dir = m.direction().invert();
            if self.dir != new_dir {
                debug!(
                    "Mid ({}) change direction: {} -> {}",
                    self.mid, self.dir, new_dir
                );

                self.need_changed_event = true;

                let was_receiving = self.dir.is_receiving();
                let was_sending = self.dir.is_sending();
                let is_receiving = new_dir.is_receiving();
                let is_sending = new_dir.is_sending();

                self.dir = new_dir;

                if was_receiving && !is_receiving {
                    // Receive buffers are dropped straight away.
                    self.clear_receive_buffers();
                }
                if !was_sending && is_sending {
                    // Dump the buffers when we are about to start sending. We don't do this
                    // on sending -> not, because we want to keep the buffer to answer straggle nacks.
                    self.clear_send_buffers();
                }
            }
        }

        // Changes in PT
        {
            let params: Vec<PayloadParams> = m
                .rtp_params()
                .into_iter()
                .map(PayloadParams::new)
                .filter(|m| config.matches(m))
                .collect();
            let mut new_pts = HashSet::new();

            for p_new in params {
                new_pts.insert(p_new.pt());

                if let Some(p_old) = self.codec_by_pt(p_new.pt()) {
                    if *p_old != p_new {
                        debug!("Ignore change in mid ({}) for pt: {}", self.mid, p_new.pt());
                    }
                } else {
                    debug!("Ignoring new pt ({}) in mid: {}", p_new.pt(), self.mid);
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

        // Update the extensions
        {
            let mut exts = Extensions::new();
            for x in m.extmaps() {
                exts.set_mapping(x);
            }
            exts.keep_same(session_exts);
            self.set_exts(exts);
        }

        // SSRC changes
        // This will always be for ReceiverSource since any incoming a=ssrc line will be
        // about the remote side's SSRC.
        {
            let infos = m.ssrc_info();
            for info in infos {
                let rx = self.get_or_create_source_rx(info.ssrc);

                if let Some(repairs) = info.repair {
                    if rx.set_repairs(repairs) {
                        self.set_equalize_sources();
                    }
                }
            }
        }

        // Simulcast configuration
        if let Some(s) = m.simulcast() {
            if s.is_munged {
                warn!("Not supporting simulcast via munging SDP");
            } else if self.simulcast().is_none() {
                // Invert before setting, since it has a recv and send config.
                self.set_simulcast(s.invert());
            }
        }
    }

    pub(crate) fn has_ssrc_rx(&self, ssrc: Ssrc) -> bool {
        self.sources_rx.iter().any(|r| r.ssrc() == ssrc)
    }

    pub(crate) fn has_ssrc_tx(&self, ssrc: Ssrc) -> bool {
        self.sources_tx.iter().any(|r| r.ssrc() == ssrc)
    }

    pub(crate) fn get_buffer_rx(
        &mut self,
        pt: Pt,
        rid: Option<Rid>,
        codec: Codec,
    ) -> &mut DepacketizingBuffer {
        self.buffers_rx
            .entry((pt, rid))
            .or_insert_with(|| DepacketizingBuffer::new(codec.into(), 100))
    }

    pub(crate) fn poll_keyframe_request(&mut self) -> Option<(Option<Rid>, KeyframeRequestKind)> {
        self.keyframe_request_rx.take()
    }

    pub(crate) fn poll_sample(&mut self) -> Option<Result<MediaData, RtcError>> {
        for ((pt, rid), buf) in &mut self.buffers_rx {
            if let Some(r) = buf.pop() {
                let codec = *self.params.iter().find(|c| c.pt() == *pt)?;
                return Some(
                    r.map(|dep| MediaData {
                        mid: self.mid,
                        pt: *pt,
                        rid: *rid,
                        params: codec,
                        time: dep.time,
                        contiguous: dep.contiguous,
                        data: dep.data,
                        ext_vals: dep.meta[0].header.ext_vals,
                        meta: dep.meta,
                    })
                    .map_err(|e| RtcError::Packet(self.mid, *pt, e)),
                );
            }
        }
        None
    }

    pub(crate) fn handle_nack(
        &mut self,
        ssrc: Ssrc,
        entries: impl Iterator<Item = NackEntry>,
    ) -> Option<()> {
        // Figure out which packetizing buffer has been used to send the entries that been nack'ed.
        let (pt, buffer) = self.buffers_tx.iter_mut().find(|(_, p)| p.has_ssrc(ssrc))?;

        // Turning NackEntry into SeqNo we need to know a SeqNo "close by" to lengthen the 16 bit
        // sequence number into the 64 bit we have in SeqNo.
        let seq_no = buffer.first_seq_no()?;
        let iter = entries.flat_map(|n| n.into_iter(seq_no));

        // Schedule all resends. They will be handled on next poll_packet
        self.resends.extend(iter.map(|seq_no| Resend {
            ssrc,
            pt: *pt,
            seq_no,
        }));

        Some(())
    }

    pub(crate) fn clear_send_buffers(&mut self) {
        self.buffers_tx.clear();
    }

    pub(crate) fn clear_receive_buffers(&mut self) {
        self.buffers_rx.clear();
    }

    pub(crate) fn regular_feedback_at(&self) -> Instant {
        self.last_regular_feedback + rr_interval(self.kind == MediaKind::Audio)
    }

    pub(crate) fn simulcast(&self) -> Option<&SdpSimulcast> {
        self.simulcast.as_ref()
    }

    pub(crate) fn set_simulcast(&mut self, s: SdpSimulcast) {
        info!("Set simulcast: {:?}", s);
        self.simulcast = Some(s);
    }

    pub(crate) fn ssrc_rx_for_rid(&self, repairs: Rid) -> Option<Ssrc> {
        self.sources_rx
            .iter()
            .find(|r| r.rid() == Some(repairs))
            .map(|r| r.ssrc())
    }

    /// The number of SSRC required to equalize the senders/receivers.
    pub(crate) fn equalize_requires_ssrcs(&self) -> usize {
        (self.sources_tx.len() as isize - self.sources_rx.len() as isize).unsigned_abs()
    }

    pub fn visit_stats(&self, snapshot: &mut StatsSnapshot) {
        if self.direction().is_receiving() {
            for s in &self.sources_rx {
                s.visit_stats(self.mid, snapshot);
            }
        }
        if self.direction().is_sending() {
            for s in &self.sources_tx {
                s.visit_stats(self.mid, snapshot);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resend {
    pub ssrc: Ssrc,
    pub pt: Pt,
    pub seq_no: SeqNo,
}

fn next_send_buffer(
    buffers_tx: &mut HashMap<Pt, PacketizingBuffer>,
) -> Option<(Pt, &mut Packetized)> {
    for (pt, buf) in buffers_tx {
        if let Some(pkt) = buf.poll_next() {
            assert!(pkt.seq_no.is_none());
            return Some((*pt, pkt));
        }
    }
    None
}

impl Default for Media {
    fn default() -> Self {
        Self {
            mid: Mid::new(),
            index: 0,
            cname: Id::<20>::random().to_string(),
            msid: Msid {
                stream_id: Id::<30>::random().to_string(),
                track_id: Id::<30>::random().to_string(),
            },
            kind: MediaKind::Video,
            exts: Extensions::new(),
            dir: Direction::SendRecv,
            params: vec![],
            sources_rx: vec![],
            sources_tx: vec![],
            last_cleanup: already_happened(),
            last_regular_feedback: already_happened(),
            buffers_rx: HashMap::new(),
            buffers_tx: HashMap::new(),
            resends: VecDeque::new(),
            need_open_event: true,
            need_changed_event: false,
            keyframe_request_rx: None,
            keyframe_request_tx: None,
            simulcast: None,
            equalize_sources: false,
            enable_nack: false,
        }
    }
}

impl Media {
    pub(crate) fn from_remote_media_line(l: &MediaLine, index: usize, exts: Extensions) -> Self {
        Media {
            mid: l.mid(),
            index,
            // These two are not reflected back, and thus added by add_pending_changes().
            // cname,
            // msid,
            kind: l.typ.clone().into(),
            exts,
            dir: l.direction().invert(), // remote direction is reverse.
            params: l.rtp_params().into_iter().map(PayloadParams::new).collect(),
            ..Default::default()
        }
    }

    // Going from AddMedia to Media is for m-lines that are pending in a Change and are sent
    // in the offer to the other side.
    pub(crate) fn from_add_media(a: AddMedia, exts: Extensions) -> Self {
        let mut media = Media {
            mid: a.mid,
            index: a.index,
            cname: a.cname,
            msid: a.msid,
            kind: a.kind,
            exts,
            dir: a.dir,
            params: a.params,
            equalize_sources: true,
            ..Default::default()
        };

        for (ssrc, repairs) in a.ssrcs {
            let tx = media.get_or_create_source_tx(ssrc);
            if let Some(repairs) = repairs {
                if tx.set_repairs(repairs) {
                    media.set_equalize_sources();
                }
            }
        }

        media
    }
}

impl From<MediaType> for MediaKind {
    fn from(v: MediaType) -> Self {
        match v {
            MediaType::Audio => MediaKind::Audio,
            MediaType::Video => MediaKind::Video,
            _ => panic!("Not MediaType::Audio or Video"),
        }
    }
}

/// Separate in wait for polonius.
fn get_source_tx(
    sources_tx: &mut [SenderSource],
    rid: Option<Rid>,
    is_rtx: bool,
) -> Option<&mut SenderSource> {
    sources_tx
        .iter_mut()
        .find(|s| rid == s.rid() && is_rtx == s.repairs().is_some())
}

/// Helper obtained by [`Media::writer()`] to send media.
///
/// This type follows a builder pattern to allow for additional data to be sent as
/// RTP extension headers.
///
/// ```no_run
/// # use str0m::{Rtc};
/// # use str0m::media::{PayloadParams, MediaData, Mid};
/// let mut rtc = Rtc::new();
///
/// // add candidates, do SDP negotation
/// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
///
/// let media = rtc.media(mid).unwrap();
///
/// // Get incoming media data from another peer
/// let data: MediaData = todo!();
/// let video_orientation = data.ext_vals.video_orientation.unwrap();
///
/// // Match incoming PT to an outgoing PT.
/// let pt = media.match_params(data.params).unwrap();
///
/// // Send data with video orientation added.
/// media.writer(pt)
///     .video_orientation(video_orientation)
///     .write(data.time, &data.data).unwrap();
/// ```
pub struct Writer<'a> {
    media: &'a mut Media,
    pt: Pt,
    rid: Option<Rid>,
    ext_vals: ExtensionValues,
}

impl<'a> Writer<'a> {
    /// Add on an Rtp Stream Id. This is typically used to separate simulcast layers.
    pub fn rid(mut self, rid: Rid) -> Self {
        self.rid = Some(rid);
        self
    }

    /// Add on audio level and voice activity. These values are communicated in the same
    /// RTP header extension, hence it makes sense setting both at the same time.
    ///
    /// Audio level is measured in negative decibel. 0 is max and a "normal" value might be -30.
    pub fn audio_level(mut self, audio_level: i8, voice_activity: bool) -> Self {
        self.ext_vals.audio_level = Some(audio_level);
        self.ext_vals.voice_activity = Some(voice_activity);
        self
    }

    /// Add video orientation. This can be used by a player on the receiver end to decide
    /// whether the video requires to be rotated to show correctly.
    pub fn video_orientation(mut self, o: VideoOrientation) -> Self {
        self.ext_vals.video_orientation = Some(o);
        self
    }

    /// Do the actual write of media. This consumed the builder.
    ///
    /// Notice that incorrect [`Pt`] values would surface as an error here, not when
    /// doing [`Media::writer()`].
    pub fn write(self, ts: MediaTime, data: &[u8]) -> Result<usize, RtcError> {
        self.media.write(self.pt, ts, data, self.rid, self.ext_vals)
    }
}

impl From<SdpSimulcast> for Simulcast {
    fn from(s: SdpSimulcast) -> Self {
        let send = s
            .send
            .iter()
            .flat_map(|s| s.iter().map(|s| s.as_stream_id().0.as_ref()))
            .map(Rid::from)
            .collect();

        let recv = s
            .recv
            .iter()
            .flat_map(|s| s.iter().map(|s| s.as_stream_id().0.as_ref()))
            .map(Rid::from)
            .collect();

        Simulcast { send, recv }
    }
}
