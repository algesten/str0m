use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::change::AddMedia;
use crate::format::Codec;
pub use crate::rtp::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid, Ssrc};

use crate::io::{Id, DATAGRAM_MTU};
use crate::packet::{DepacketizingBuffer, MediaKind, Packetized, QueuePriority, QueueSnapshot};
use crate::packet::{PacketizedMeta, PacketizingBuffer, QueueState};
use crate::rtp::{ExtensionMap, Fir, FirEntry, NackEntry, Pli, Rtcp};
use crate::rtp::{RtcpFb, RtpHeader, SdesType};
use crate::rtp::{SeqNo, MAX_BLANK_PADDING_PAYLOAD_SIZE, SRTP_BLOCK_SIZE, SRTP_OVERHEAD};
use crate::sdp::{MediaLine, Msid, Simulcast as SdpSimulcast};
use crate::stats::StatsSnapshot;
use crate::util::already_happened;
use crate::util::value_history::ValueHistory;
use crate::RtcError;

use super::receiver::ReceiverSource;
use super::sender::SenderSource;
use super::{KeyframeRequestKind, MediaData, PayloadParams};

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

// Time between regular receiver reports.
// https://www.rfc-editor.org/rfc/rfc8829#section-5.1.2
// Should technically be 4 seconds according to spec, but libWebRTC
// expects video to be every second, and audio every 5 seconds.
const RR_INTERVAL_VIDEO: Duration = Duration::from_millis(1000);
const RR_INTERVAL_AUDIO: Duration = Duration::from_millis(5000);

/// The smallest size of padding for which we attempt to use a spurious resend. For padding
/// requests smaller than this we use blank packets instead.
const MIN_SPURIOUS_PADDING_SIZE: usize = 50;

fn rr_interval(audio: bool) -> Duration {
    if audio {
        RR_INTERVAL_AUDIO
    } else {
        RR_INTERVAL_VIDEO
    }
}
#[derive(Debug)]
pub(crate) struct MediaInner {
    /// Three letter identifier of this media.
    mid: Mid,

    /// The index of this media line in the Session::media Vec.
    index: usize,

    /// When converting media lines to SDP, it's easier to represent the app m-line
    /// as a MediaInner. This field is true when we do that. No Session::medias will have
    /// this set to true – they only exist temporarily.
    pub(crate) app_tmp: bool,

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

    /// Receiving sources (SSRC).
    ///
    /// These are created first time we observe the SSRC in an incoming RTP packet.
    /// Each source keeps track of packet loss, nack, reports etc. Receiving sources are
    /// cleaned up when we haven't received any data for the SSRC for a while.
    sources_rx: Vec<ReceiverSource>,

    /// Sender sources (SSRC).
    ///
    /// Created when we configure new media via Changes API.
    sources_tx: Vec<SenderSource>,

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

    /// Queue of packets to send for padding.
    padding: VecDeque<Padding>,

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

    /// Tells whether nack is enabled for this media.
    enable_nack: bool,

    /// History of bytes transmitted on this media.
    bytes_transmitted: ValueHistory<u64>,

    /// History of bytes re-transmitted.
    bytes_retransmitted: ValueHistory<u64>,

    /// Merged queue state, set to None if we need to recalculate it.
    queue_state: Option<QueueState>,

    /// Enqueing to the PacketizingBuffer requires a "queued_at" field
    /// which is "now". We don't want write() to drive time forward,
    /// which means we are temporarily storing the packets here until
    /// next handle_timeout.
    ///
    /// The expected behavior is:
    /// 1. MediaWriter::write()
    /// 2. to_packetize.push()
    /// 3. poll_output -> timeout straight away
    /// 4. handle_timeout(straight away)
    /// 5. to_packetize.pop()
    to_packetize: VecDeque<ToPacketize>,

    /// Whether we are running in RTP-mode.
    pub(crate) rtp_mode: bool,
}

#[derive(Debug)]
enum Padding {
    /// An empty padding packet containing all zeros.
    Blank {
        ssrc: Ssrc,
        pt: Pt,
        requested_at: Instant,
        size: usize,
    },
    /// A spurious resend of a previous media packet to act as padding.
    Spurious(Resend),
}

struct NextPacket<'a> {
    pt: Pt,
    ssrc: Ssrc,
    seq_no: SeqNo,
    body: NextPacketBody<'a>,
}

#[derive(Debug)]
struct ToPacketize {
    pt: Pt,
    data: Vec<u8>,
    meta: PacketizedMeta,
    rtp_mode_header: Option<RtpHeader>,
}

enum NextPacketBody<'a> {
    /// A regular packetized packet
    Regular { pkt: &'a Packetized },
    /// A resend of a previously sent packet
    Resend {
        pkt: &'a Packetized,
        orig_seq_no: Option<SeqNo>,
    },
    /// An blank padding packet to be generated.
    Blank { len: u8 },
}

impl MediaInner {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn cname(&self) -> &str {
        &self.cname
    }

    pub fn set_cname(&mut self, cname: String) {
        self.cname = cname;
    }

    pub fn msid(&self) -> &Msid {
        &self.msid
    }

    pub fn set_msid(&mut self, msid: Msid) {
        self.msid = msid;
    }

    pub fn kind(&self) -> MediaKind {
        self.kind
    }

    pub fn set_exts(&mut self, exts: ExtensionMap) {
        if self.exts != exts {
            info!("Set {:?} extensions: {:?}", self.mid, exts);
            self.exts = exts;
        }
    }

    pub fn exts(&self) -> &ExtensionMap {
        &self.exts
    }

    pub fn direction(&self) -> Direction {
        self.dir
    }

    fn params_by_pt(&self, pt: Pt) -> Option<&PayloadParams> {
        self.params.iter().find(|c| c.pt() == pt)
    }

    pub fn payload_params(&self) -> &[PayloadParams] {
        &self.params
    }

    pub fn match_params(&self, params: PayloadParams) -> Option<Pt> {
        let c = self.params.iter().max_by_key(|p| p.match_score(&params))?;
        c.match_score(&params)?; // avoid None, which isn't a match.
        Some(c.pt())
    }

    /// Write to the packetizer.
    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &mut self,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: &[u8],
        rid: Option<Rid>,
        ext_vals: ExtensionValues,
        rtp_mode_header: Option<RtpHeader>,
        send_buffer_audio: usize,
        send_buffer_video: usize,
    ) -> Result<(), RtcError> {
        if !self.dir.is_sending() {
            return Err(RtcError::NotSendingDirection(self.dir));
        }

        let Some(spec) = self.params_by_pt(pt).map(|p| p.spec()) else {
            return Err(RtcError::UnknownPt(pt));
        };

        // Implicitly if we have an rtp mode header, the codec must be Null.
        let codec = if rtp_mode_header.is_some() {
            Codec::Null
        } else {
            spec.codec
        };

        // Never want to check this for the null codec.
        let is_audio = spec.codec.is_audio();

        // The SSRC is figured out given the simulcast level.
        let tx = get_source_tx(&mut self.sources_tx, rid, false).ok_or(RtcError::NoSenderSource)?;

        let ssrc = tx.ssrc();
        tx.update_clocks(rtp_time, wallclock);

        // We don't actually want this buffer here, but it must be created before we
        // get to the do_packetize() (as part of handle_timeout).
        let _ = self.buffers_tx.entry(pt).or_insert_with(|| {
            let max_retain = if is_audio {
                send_buffer_audio
            } else {
                send_buffer_video
            };
            PacketizingBuffer::new(codec.into(), max_retain)
        });

        trace!(
            "Write to packetizer rtp_time: {:?} bytes: {}",
            rtp_time,
            data.len()
        );

        let meta = PacketizedMeta {
            rtp_time,
            ssrc,
            rid,
            ext_vals,
        };

        self.to_packetize.push_back(ToPacketize {
            pt,
            data: data.to_vec(),
            meta,
            rtp_mode_header,
        });

        Ok(())
    }

    /// Does the actual packetizing on handle_timeout()
    fn do_packetize(&mut self, now: Instant) -> Result<(), RtcError> {
        const RTP_SIZE: usize = DATAGRAM_MTU - SRTP_OVERHEAD;
        // align to SRTP block size to minimize padding needs
        const MTU: usize = RTP_SIZE - RTP_SIZE % SRTP_BLOCK_SIZE;

        while let Some(t) = self.to_packetize.pop_front() {
            let pt = t.pt;

            let buf = self
                .buffers_tx
                .get_mut(&t.pt)
                .expect("write() to create buffer");

            let overflow = if self.rtp_mode {
                let rtp_header = t.rtp_mode_header.expect("rtp header in rtp mode");
                buf.push_rtp_packet(now, t.data, t.meta, rtp_header)
            } else {
                match buf.push_sample(now, &t.data, t.meta, MTU) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(RtcError::Packet(self.mid, t.pt, e));
                    }
                }
            };

            if overflow {
                self.resends.retain(|r| r.pt != pt);
                self.padding.retain(|p| p.pt() != pt);
            }

            // Invalidate cached queue_state.
            self.queue_state = None;
        }

        Ok(())
    }

    pub(crate) fn write_rtp(
        &mut self,
        pt: Pt,
        wallclock: Instant,
        packet: &[u8],
        exts: &ExtensionMap,
        send_buffer_audio: usize,
        send_buffer_video: usize,
    ) -> Result<(), RtcError> {
        let Some(spec) = self.params_by_pt(pt).map(|p| p.spec()) else {
            return Err(RtcError::UnknownPt(pt));
        };

        let header = RtpHeader::parse(packet, exts)
            .ok_or_else(|| RtcError::Other("Failed to parse RTP header".into()))?;

        // Remove header from packet.
        let packet = &packet[header.header_len..];

        let rid = header.ext_vals.rid;
        // This doesn't need to be lengthened
        let rtp_time = MediaTime::new(header.timestamp as i64, spec.clock_rate as i64);

        self.write(
            pt,
            wallclock,
            rtp_time,
            packet,
            rid,
            header.ext_vals,
            Some(header),
            send_buffer_audio,
            send_buffer_video,
        )?;

        Ok(())
    }

    pub fn is_request_keyframe_possible(&self, kind: KeyframeRequestKind) -> bool {
        // TODO: It's possible to have different set of feedback enabled for different
        // payload types. I.e. we could have FIR enabled for H264, but not for VP8.
        // We might want to make this check more fine grained by testing which PT is
        // in "active use" right now.
        self.params.iter().any(|r| match kind {
            KeyframeRequestKind::Pli => r.fb_pli,
            KeyframeRequestKind::Fir => r.fb_fir,
        })
    }

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

    pub fn poll_packet(
        &mut self,
        now: Instant,
        exts: &ExtensionMap,
        twcc: &mut u64,
        buf: &mut Vec<u8>,
    ) -> Option<PolledPacket> {
        let mid = self.mid;

        let (next, is_padding) = if let Some(next) = self.poll_packet_resend_to_cap(now) {
            (next, false)
        } else if let Some(next) = self.poll_packet_regular(now) {
            (next, false)
        } else if let Some(next) = self.poll_packet_padding(now) {
            (next, true)
        } else {
            return None;
        };

        let mut header = RtpHeader {
            payload_type: next.pt,
            sequence_number: *next.seq_no as u16,
            ssrc: next.ssrc,
            timestamp: next.body.timestamp(),
            ext_vals: next.body.ext_vals(),
            marker: next.body.marker(),
            ..Default::default()
        };

        // We can fill out as many values we want here, only the negotiated ones will
        // be used when writing the RTP packet.
        //
        // These need to match `Extension::is_supported()` so we are sending what we are
        // declaring we support.
        header.ext_vals.abs_send_time = Some(MediaTime::new_ntp_time(now));
        header.ext_vals.mid = Some(mid);
        header.ext_vals.transport_cc = Some(*twcc as u16);
        *twcc += 1;

        buf.resize(2000, 0);
        let header_len = header.write_to(buf, exts);
        assert!(header_len % 4 == 0, "RTP header must be multiple of 4");
        header.header_len = header_len;

        let mut body_out = &mut buf[header_len..];

        // For resends, the original seq_no is inserted before the payload.
        let mut original_seq_len = 0;
        if let Some(orig_seq_no) = next.body.orig_seq_no() {
            original_seq_len = RtpHeader::write_original_sequence_number(body_out, orig_seq_no);
            body_out = &mut body_out[original_seq_len..];
        }

        let body_len = match next.body {
            NextPacketBody::Regular { pkt } | NextPacketBody::Resend { pkt, .. } => {
                let body_len = pkt.data.len();
                body_out[..body_len].copy_from_slice(&pkt.data);

                // pad for SRTP
                let pad_len = RtpHeader::pad_packet(
                    &mut buf[..],
                    header_len,
                    body_len + original_seq_len,
                    SRTP_BLOCK_SIZE,
                );

                body_len + original_seq_len + pad_len
            }
            NextPacketBody::Blank { len } => {
                let len = RtpHeader::create_padding_packet(
                    &mut buf[..],
                    len,
                    header_len,
                    SRTP_BLOCK_SIZE,
                );
                if len == 0 {
                    return None;
                }

                len
            }
        };
        buf.truncate(header_len + body_len);

        #[cfg(feature = "_internal_dont_use_log_stats")]
        if let Some(delay) = next.body.queued_at().map(|i| now.duration_since(i)) {
            crate::log_stat!("QUEUE_DELAY", header.ssrc, delay.as_secs_f64() * 1000.0);
        }

        Some(PolledPacket {
            header,
            seq_no: next.seq_no,
            is_padding,
            payload_size: body_len,
        })
    }

    fn poll_packet_resend_to_cap(&mut self, now: Instant) -> Option<NextPacket> {
        let from = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
        let bytes_transmitted = self.bytes_transmitted.sum_since(from);
        let bytes_retransmitted = self.bytes_retransmitted.sum_since(from);
        let ratio = bytes_retransmitted as f32 / (bytes_retransmitted + bytes_transmitted) as f32;
        let ratio = if ratio.is_finite() { ratio } else { 0_f32 };

        // If we hit the cap, stop doing resends by clearing those we have queued.
        if ratio > 0.15_f32 {
            self.resends.clear();

            // Invalidate cached queue state.
            self.queue_state = None;

            return None;
        }

        self.poll_packet_resend(now, false)
    }

    fn poll_packet_resend(&mut self, now: Instant, is_padding: bool) -> Option<NextPacket<'_>> {
        if !self.resends.is_empty() {
            // Must clear cache because the loop will pop at least one resend which modifies the
            // queue state
            self.queue_state = None;
        }

        let (resend, source) = loop {
            let resend = self.resends.pop_front()?;

            // If there is no buffer for this resend, we return None. This is
            // a weird situation though, since it means the other side sent a nack for
            // an SSRC that matched this Media, but didn't match a buffer_tx.
            let buffer = self.buffers_tx.values().find(|p| p.ssrc() == resend.ssrc)?;

            let pkt = buffer.get(resend.seq_no);

            // The seq_no could simply be too old to exist in the buffer, in which
            // case we will not do a resend.
            let Some(pkt) = pkt else {
                continue;
            };

            // The send source, to get a contiguous seq_no for the resend.
            // Audio should not be resent, so this also gates whether we are doing resends at all.
            let source = match get_source_tx(&mut self.sources_tx, pkt.meta.rid, true) {
                Some(v) => v,
                None => continue,
            };

            break (resend, source);
        };

        let buffer = self.buffers_tx.get_mut(&resend.pt).unwrap();
        let pkt = buffer.get(resend.seq_no).unwrap();

        if !is_padding {
            source.update_packet_counts(pkt.data.len() as u64, true);
            self.bytes_retransmitted.push(now, pkt.data.len() as u64);
        }

        let seq_no = source.next_seq_no(now, None);

        // The resend ssrc. This would correspond to the RTX PT for video.
        let ssrc_rtx = source.ssrc();

        let orig_seq_no = Some(resend.seq_no);

        // Check that our internal state of organizing SSRC for senders is correct.
        assert_eq!(pkt.meta.ssrc, resend.ssrc);
        assert_eq!(source.repairs(), Some(resend.ssrc));

        // If the resent PT doesn't exist, the state is not correct as per above.
        let pt = pt_rtx(&self.params, resend.pt).expect("Resend PT");

        Some(NextPacket {
            pt,
            ssrc: ssrc_rtx,
            seq_no,
            body: NextPacketBody::Resend { pkt, orig_seq_no },
        })
    }

    fn poll_packet_regular(&mut self, now: Instant) -> Option<NextPacket<'_>> {
        // exit via ? here is ok since that means there is nothing to send.
        let (pt, pkt) = next_send_buffer(&self.buffers_tx)?;

        // Force recaching since packetizer changed.
        self.queue_state = None;

        let source = self
            .sources_tx
            .iter_mut()
            .find(|s| s.ssrc() == pkt.meta.ssrc)
            .expect("SenderSource for packetized write");

        source.update_packet_counts(pkt.data.len() as u64, false);
        self.bytes_transmitted.push(now, pkt.data.len() as u64);

        //  In rtp_mode, we just use the incoming sequence number.
        let wanted = pkt.rtp_mode_header.as_ref().map(|h| h.sequence_number);
        let seq_no = source.next_seq_no(now, wanted);

        let buf = self
            .buffers_tx
            .get_mut(&pt)
            .expect("buffer for next packet");

        buf.update_next(seq_no);

        let pkt = buf.take_next(now);

        Some(NextPacket {
            pt,
            seq_no,
            ssrc: pkt.meta.ssrc,
            body: NextPacketBody::Regular { pkt },
        })
    }

    fn poll_packet_padding(&mut self, now: Instant) -> Option<NextPacket> {
        loop {
            let padding = self.padding.pop_front()?;

            // Force recaching since padding changed.
            self.queue_state = None;

            match padding {
                Padding::Blank { ssrc, pt, size, .. } => {
                    let source_tx = get_or_create_source_tx(
                        &mut self.sources_tx,
                        &mut self.equalize_sources,
                        ssrc,
                    );
                    let seq_no = source_tx.next_seq_no(now, None);

                    trace!(
                        "Generating blank padding packet of size {size} on {ssrc} with pt: {pt}"
                    );
                    return Some(NextPacket {
                        pt,
                        ssrc,
                        seq_no,
                        body: NextPacketBody::Blank { len: size as u8 },
                    });
                }
                Padding::Spurious(resend) => {
                    // If there is no buffer for this padding, we return None. This is
                    // a weird situation though, since it means we queued padding for a buffer we don't
                    // have.
                    let Some(buffer) = self
                        .buffers_tx
                        .values()
                        .find(|p| p.ssrc() == padding.ssrc()) else {
                            // This can happen for example case buffers were
                            // cleared (i.e. a change of media direction)
                            continue;
                        };

                    let pkt = buffer.get(resend.seq_no);

                    // The seq_no could simply be too old to exist in the buffer, in which
                    // case we will not do a resend.
                    let Some(pkt) = pkt else {
                        continue;
                    };

                    // The send source, to get a contiguous seq_no for the resend.
                    // Audio should not be resent, so this also gates whether we are doing resends at all.
                    let source = match get_source_tx(&mut self.sources_tx, pkt.meta.rid, true) {
                        Some(v) => v,
                        None => continue,
                    };

                    let seq_no = source.next_seq_no(now, None);

                    // The resend ssrc. This would correspond to the RTX PT for video.
                    let ssrc_rtx = source.ssrc();

                    let orig_seq_no = Some(resend.seq_no);

                    // Check that our internal state of organizing SSRC for senders is correct.
                    assert_eq!(pkt.meta.ssrc, resend.ssrc);
                    assert_eq!(source.repairs(), Some(resend.ssrc));

                    // If the resent PT doesn't exist, the state is not correct as per above.
                    let pt = pt_rtx(&self.params, resend.pt).expect("Resend PT");

                    return Some(NextPacket {
                        pt,
                        ssrc: ssrc_rtx,
                        seq_no,
                        body: NextPacketBody::Resend { pkt, orig_seq_no },
                    });
                }
            };
        }
    }

    /// Generate padding and queue it to be sent later.
    pub fn generate_padding(&mut self, now: Instant, mut pad_size: usize) {
        // Only do padding packets if we are using RTX, or we will increase the seq_no
        // on the main SSRC for filler stuff.
        if !self.has_tx_rtx() {
            panic!("generate_padding() called on non-RTX media");
        }
        if !self.direction().is_sending() {
            panic!("generate_padding() called on non-sending media");
        }
        assert!(
            self.queue_state
                .map(|q| q.snapshot.packet_count == 0)
                .unwrap_or(true),
            "Attempted to queue padding when there were other packets queued"
        );

        while pad_size > 0 {
            // TODO: This function should be split into two halves, but because of the borrow checker
            // it's hard to construct.

            // This first scope tries to send a spurious (unasked for) resend of a packet already sent.
            if pad_size > MIN_SPURIOUS_PADDING_SIZE {
                let pt = self
                    .buffers_tx
                    .iter()
                    .map(|(pt, buffer)| (pt, buffer.history_size()))
                    .filter(|(_, size)| *size > 0)
                    // Use the last PT i.e. the one that has the most RTX history, this is a poor
                    // approximation for most recent sends.
                    .max_by_key(|(_, size)| *size)
                    .map(|(pt, _)| *pt);

                // If we find a pt above, we do a spurious (unasked for) resend of this packet.
                if let Some(pt) = pt {
                    let buffer = get_buffer_tx(&self.buffers_tx, pt)
                        .expect("the buffer to exist as verified previously");

                    // Find a historic packet that is smaller than this max size. The max size
                    // is a headroom since we can accept slightly larger padding than asked for.
                    let max_size = pad_size * 2;
                    if let Some(packet) = buffer.historic_packet_smaller_than(max_size) {
                        let seq_no = packet.seq_no.expect(
                            "this packet to have been sent and therefore have a sequence number",
                        );
                        // Saturating sub because we can overflow and want to stop when that
                        // happens.
                        pad_size = pad_size.saturating_sub(packet.data.len());
                        trace!(
                            "Queued {} bytes worth of resend padding, seq_no = {seq_no}",
                            packet.data.len()
                        );

                        self.padding.push_back(Padding::Spurious(Resend {
                            pt,
                            body_size: packet.data.len(),
                            ssrc: packet.meta.ssrc,
                            seq_no,
                            queued_at: now,
                        }));

                        continue;
                    }
                }
            }

            // This second scope sends an empty padding packet. This is a fallback strategy if we fail
            // to find a suitable rtx packet above.
            // NB: If we cannot generate padding here for some reason we'll get stuck forever.
            {
                let Some(&pt) = self.buffers_tx.keys().next() else {
                    panic!("No PT to send blank padding on");
                };
                let Some(pt_rtx) = pt_rtx(&self.params, pt) else {
                    panic!("No PT to send blank padding on");
                };
                let ssrc_rtx = self
                    .sources_tx
                    .iter()
                    .find(|s| s.is_rtx())
                    .map(|s| s.ssrc())
                    .expect("at least one rtx source");

                let padding = pad_size.clamp(SRTP_BLOCK_SIZE, MAX_BLANK_PADDING_PAYLOAD_SIZE);

                // Saturating sub because we can overflow and want to stop when that
                // happens.
                pad_size = pad_size.saturating_sub(padding);

                trace!("Queued {padding} bytes worth of blank padding");
                self.padding.push_back(Padding::Blank {
                    ssrc: ssrc_rtx,
                    pt: pt_rtx,
                    requested_at: now,
                    size: padding,
                });
            }
        }

        // Clear queue state cache
        self.queue_state = None;
    }

    pub fn get_or_create_source_rx(&mut self, ssrc: Ssrc) -> &mut ReceiverSource {
        let maybe_idx = self.sources_rx.iter().position(|r| r.ssrc() == ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_rx[idx]
        } else {
            self.equalize_sources = true;
            self.sources_rx.push(ReceiverSource::new(ssrc));
            self.sources_rx.last_mut().unwrap()
        }
    }

    pub fn get_or_create_source_tx(&mut self, ssrc: Ssrc) -> &mut SenderSource {
        get_or_create_source_tx(&mut self.sources_tx, &mut self.equalize_sources, ssrc)
    }

    pub fn set_equalize_sources(&mut self) {
        self.equalize_sources = true;
    }

    pub fn equalize_sources(&self) -> bool {
        self.equalize_sources
    }

    pub fn do_equalize_sources(&mut self, new_ssrc: &mut impl Iterator<Item = Ssrc>) {
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

    pub fn get_params(&self, pt: Pt) -> Option<&PayloadParams> {
        self.params
            .iter()
            .find(|p| p.pt() == pt || p.resend == Some(pt))
    }

    pub fn has_nack(&mut self) -> bool {
        if !self.enable_nack {
            return false;
        }
        self.sources_rx
            .iter_mut()
            .filter(|s| !s.is_rtx())
            .any(|s| s.has_nack())
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), RtcError> {
        self.do_packetize(now)
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.packetize_at()
    }

    fn packetize_at(&self) -> Option<Instant> {
        if self.to_packetize.is_empty() {
            None
        } else {
            // If we got things to packetize, do it straight away.
            Some(already_happened())
        }
    }

    pub fn source_tx_ssrcs(&self) -> impl Iterator<Item = Ssrc> + '_ {
        self.sources_tx.iter().map(|s| s.ssrc())
    }

    pub fn maybe_create_keyframe_request(
        &mut self,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) {
        let Some((ssrc, kind)) = self.keyframe_request_tx.take() else {
            return;
        };

        // Unwrap is ok, because MediaWriter ensures the ReceiverSource exists.
        let rx = self
            .sources_rx
            .iter_mut()
            .find(|s| s.ssrc() == ssrc)
            .unwrap();

        rx.update_with_keyframe_request(kind);

        match kind {
            KeyframeRequestKind::Pli => feedback.push_back(Rtcp::Pli(Pli { sender_ssrc, ssrc })),
            KeyframeRequestKind::Fir => feedback.push_back(Rtcp::Fir(Fir {
                sender_ssrc,
                reports: FirEntry {
                    ssrc,
                    seq_no: rx.next_fir_seq_no(),
                }
                .into(),
            })),
        }
    }

    /// Creates sender info and receiver reports for all senders/receivers
    pub fn maybe_create_regular_feedback(
        &mut self,
        now: Instant,
        sender_ssrc: Ssrc,
        feedback: &mut VecDeque<Rtcp>,
    ) -> Option<()> {
        if now < self.regular_feedback_at() {
            return None;
        }

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

                if !rr.reports.is_empty() {
                    let l = rr.reports[rr.reports.len() - 1].fraction_lost;
                    s.update_loss(l);
                }

                debug!("Created feedback RR: {:?}", rr);
                feedback.push_back(Rtcp::ReceiverReport(rr));

                let er = s.create_extended_receiver_report(now);
                debug!("Created feedback extended receiver report: {:?}", er);
                feedback.push_back(Rtcp::ExtendedReport(er));
            }
        }

        // Update timestamp to move time when next is created.
        self.last_regular_feedback = now;

        Some(())
    }

    /// Creates nack reports for receivers, if needed.
    pub fn create_nack(&mut self, sender_ssrc: Ssrc, feedback: &mut VecDeque<Rtcp>) {
        if !self.enable_nack {
            return;
        }
        for s in &mut self.sources_rx {
            if s.is_rtx() {
                continue;
            }
            if let Some(nacks) = s.create_nacks() {
                for mut nack in nacks {
                    nack.sender_ssrc = sender_ssrc;

                    debug!("Created feedback NACK: {:?}", nack);
                    feedback.push_back(Rtcp::Nack(nack));
                    s.update_with_nack();
                }
            }
        }
    }

    /// Apply incoming RTCP feedback.
    pub fn handle_rtcp_fb(&mut self, now: Instant, fb: RtcpFb) -> Option<()> {
        debug!("Handle RTCP feedback: {:?}", fb);

        if fb.is_for_rx() {
            self.handle_rtcp_fb_rx(now, fb)?;
        } else {
            self.handle_rtcp_fb_tx(now, fb)?;
        }

        Some(())
    }

    pub fn handle_rtcp_fb_rx(&mut self, now: Instant, fb: RtcpFb) -> Option<()> {
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
            DlrrItem(v) => {
                source_rx.set_dlrr_item(now, v);
            }
            Goodbye(_v) => {
                // For some reason, Chrome sends a Goodbye on every SDP negotiation for all active
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

    pub fn handle_rtcp_fb_tx(&mut self, now: Instant, fb: RtcpFb) -> Option<()> {
        let ssrc = fb.ssrc();

        let source_tx = self.sources_tx.iter_mut().find(|s| s.ssrc() == ssrc)?;

        use RtcpFb::*;
        match fb {
            ReceptionReport(r) => source_tx.update_with_rr(now, r),
            Nack(ssrc, list) => {
                source_tx.increase_nacks();
                let entries = list.into_iter();
                self.handle_nack(ssrc, entries, now)?;
            }
            Pli(_) => {
                source_tx.increase_plis();
                self.keyframe_request_rx = Some((source_tx.rid(), KeyframeRequestKind::Pli));
            }
            Fir(_) => {
                source_tx.increase_firs();
                self.keyframe_request_rx = Some((source_tx.rid(), KeyframeRequestKind::Fir));
            }
            Twcc(_) => unreachable!("TWCC should be handled on session level"),
            _ => {}
        }

        Some(())
    }

    pub fn enable_nack(&mut self) {
        debug!("Enable NACK feedback ({:?})", self.mid);
        self.enable_nack = true;
    }

    pub fn set_direction(&mut self, new_dir: Direction) {
        if self.dir == new_dir {
            return;
        }
        debug!(
            "Mid ({}) change direction: {} -> {}",
            self.mid, self.dir, new_dir
        );

        // Clear cache
        self.queue_state = None;
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

    pub fn has_ssrc_rx(&self, ssrc: Ssrc) -> bool {
        self.sources_rx.iter().any(|r| r.ssrc() == ssrc)
    }

    pub fn has_ssrc_tx(&self, ssrc: Ssrc) -> bool {
        self.sources_tx.iter().any(|r| r.ssrc() == ssrc)
    }

    pub fn get_buffer_rx(
        &mut self,
        pt: Pt,
        rid: Option<Rid>,
        codec: Codec,
        hold_back: usize,
    ) -> &mut DepacketizingBuffer {
        self.buffers_rx
            .entry((pt, rid))
            .or_insert_with(|| DepacketizingBuffer::new(codec.into(), hold_back))
    }

    pub fn poll_keyframe_request(&mut self) -> Option<(Option<Rid>, KeyframeRequestKind)> {
        self.keyframe_request_rx.take()
    }

    pub fn poll_sample(&mut self) -> Option<Result<MediaData, RtcError>> {
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

    pub fn handle_nack(
        &mut self,
        ssrc: Ssrc,
        entries: impl Iterator<Item = NackEntry>,
        now: Instant,
    ) -> Option<()> {
        // Figure out which packetizing buffer has been used to send the entries that been nack'ed.
        let (pt, buffer) = self.buffers_tx.iter_mut().find(|(_, p)| p.ssrc() == ssrc)?;

        // Turning NackEntry into SeqNo we need to know a SeqNo "close by" to lengthen the 16 bit
        // sequence number into the 64 bit we have in SeqNo.
        let seq_no = buffer.first_seq_no()?;
        let iter = entries.flat_map(|n| n.into_iter(seq_no));

        // Invalidate cached queue_state.
        self.queue_state = None;

        // Schedule all resends. They will be handled on next poll_packet
        for seq_no in iter {
            // This keeps the TotalQueue updated in the buffer so the QueueState will
            // account for resends.
            let Some(pkt) = buffer.get(seq_no) else {
                continue;
            };

            let resend = Resend {
                ssrc,
                pt: *pt,
                seq_no,
                body_size: pkt.data.len(),
                queued_at: now,
            };
            self.resends.push_back(resend);
        }

        Some(())
    }

    pub fn clear_send_buffers(&mut self) {
        self.buffers_tx.clear();
    }

    pub fn clear_receive_buffers(&mut self) {
        self.buffers_rx.clear();
    }

    pub fn regular_feedback_at(&self) -> Instant {
        self.last_regular_feedback + rr_interval(self.kind == MediaKind::Audio)
    }

    pub fn simulcast(&self) -> Option<&SdpSimulcast> {
        self.simulcast.as_ref()
    }

    pub fn set_simulcast(&mut self, s: SdpSimulcast) {
        info!("Set simulcast: {:?}", s);
        self.simulcast = Some(s);
    }

    pub fn ssrc_rx_for_rid(&self, repairs: Rid) -> Option<Ssrc> {
        self.sources_rx
            .iter()
            .find(|r| r.rid() == Some(repairs))
            .map(|r| r.ssrc())
    }

    /// The number of SSRC required to equalize the senders/receivers.
    pub fn equalize_requires_ssrcs(&self) -> usize {
        (self.sources_tx.len() as isize - self.sources_rx.len() as isize).unsigned_abs()
    }

    pub fn visit_stats(&mut self, now: Instant, snapshot: &mut StatsSnapshot) {
        for s in &self.sources_rx {
            s.visit_stats(now, self.mid, snapshot);
        }
        for s in &mut self.sources_tx {
            s.visit_stats(now, self.mid, snapshot);
        }
    }

    /// Return the queue state for outbound RTP traffic for this media.
    ///
    /// For the purposes of pacing each media is treated as its own packet queue. Internally this
    /// is spread across many [`PacketizingBuffer`] which is where the actual packets are queued.
    pub fn buffers_tx_queue_state(&mut self, now: Instant) -> QueueState {
        // If it is cached, we don't need to recalculate it.
        if let Some(queue_state) = self.queue_state {
            return queue_state;
        }

        let init = QueueSnapshot::default();
        let mut snapshot = self.buffers_tx.values_mut().fold(init, |mut snap, b| {
            snap.merge(&b.queue_snapshot(now));

            snap
        });

        for resend in &self.resends {
            let queued = now - resend.queued_at;
            let snap = QueueSnapshot {
                created_at: now,
                size: resend.body_size,
                packet_count: 1,
                total_queue_time_origin: queued,
                ..Default::default()
            };
            snapshot.merge(&snap);
        }

        snapshot.merge(&self.padding_snapshot(now));

        let state = QueueState {
            mid: self.mid,
            is_audio: self.kind.is_audio(),
            use_for_padding: self.kind.is_video()
                && self.has_tx_rtx()
                && snapshot.has_ever_sent()
                && self.direction().is_sending(),
            snapshot,
        };

        // Cache it.
        self.queue_state = Some(state);

        state
    }

    /// Test if any source_tx in this channel has rtx.
    fn has_tx_rtx(&self) -> bool {
        self.sources_tx.iter().any(|s| s.is_rtx())
    }

    fn padding_snapshot(&self, now: Instant) -> QueueSnapshot {
        let mut snapshot = QueueSnapshot {
            created_at: now,
            ..Default::default()
        };
        for padding in &self.padding {
            let (size, queued_at) = match padding {
                Padding::Blank {
                    requested_at, size, ..
                } => (*size, *requested_at),
                Padding::Spurious(Resend {
                    body_size,
                    queued_at,
                    ..
                }) => (*body_size, *queued_at),
            };

            snapshot.merge(&QueueSnapshot {
                created_at: now,
                size,
                packet_count: 1,
                total_queue_time_origin: now - queued_at,
                last_emitted: None,
                first_unsent: Some(queued_at),
                priority: QueuePriority::Padding,
            });
        }

        snapshot
    }
}

pub struct PolledPacket {
    pub header: RtpHeader,
    pub seq_no: SeqNo,
    pub is_padding: bool,
    pub payload_size: usize,
}

// returns the corresponding rtx pt counterpart, if any
fn pt_rtx(params: &[PayloadParams], pt: Pt) -> Option<Pt> {
    params.iter().find(|p| p.pt() == pt)?.resend
}

impl<'a> NextPacketBody<'a> {
    fn timestamp(&self) -> u32 {
        use NextPacketBody::*;
        match self {
            Regular { pkt } => pkt.meta.rtp_time.numer() as u32,
            Resend { pkt, .. } => pkt.meta.rtp_time.numer() as u32,
            Blank { .. } => 0,
        }
    }

    fn ext_vals(&self) -> ExtensionValues {
        use NextPacketBody::*;
        match self {
            Regular { pkt } => pkt.meta.ext_vals,
            Resend { pkt, .. } => pkt.meta.ext_vals,
            Blank { .. } => ExtensionValues::default(),
        }
    }

    fn marker(&self) -> bool {
        use NextPacketBody::*;
        match self {
            Regular { pkt } => pkt.marker,
            Resend { pkt, .. } => pkt.marker,
            Blank { .. } => false,
        }
    }

    fn orig_seq_no(&self) -> Option<SeqNo> {
        use NextPacketBody::*;
        match self {
            Regular { .. } => None,
            Resend { orig_seq_no, .. } => *orig_seq_no,
            Blank { .. } => None,
        }
    }

    #[cfg(feature = "_internal_dont_use_log_stats")]
    fn queued_at(&self) -> Option<Instant> {
        use NextPacketBody::*;
        match self {
            Regular { pkt } => Some(pkt.queued_at),
            // TODO: Accurate queued_at for resends
            Resend { .. } => None,
            Blank { .. } => None,
        }
    }
}

impl Padding {
    fn ssrc(&self) -> Ssrc {
        match self {
            Padding::Blank { ssrc, .. } => *ssrc,
            Padding::Spurious(resend) => resend.ssrc,
        }
    }

    fn pt(&self) -> Pt {
        match self {
            Padding::Blank { pt, .. } => *pt,
            Padding::Spurious(s) => s.pt,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resend {
    pub ssrc: Ssrc,
    pub pt: Pt,
    pub seq_no: SeqNo,
    pub body_size: usize,
    pub queued_at: Instant,
}

fn next_send_buffer(buffers_tx: &HashMap<Pt, PacketizingBuffer>) -> Option<(Pt, &Packetized)> {
    for (pt, buf) in buffers_tx {
        if let Some(pkt) = buf.maybe_next() {
            assert!(pkt.seq_no.is_none());
            return Some((*pt, pkt));
        }
    }
    None
}

impl Default for MediaInner {
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
            sources_rx: vec![],
            sources_tx: vec![],
            last_regular_feedback: already_happened(),
            buffers_rx: HashMap::new(),
            buffers_tx: HashMap::new(),
            resends: VecDeque::new(),
            padding: VecDeque::new(),
            need_open_event: true,
            need_changed_event: false,
            keyframe_request_rx: None,
            keyframe_request_tx: None,
            simulcast: None,
            equalize_sources: false,
            enable_nack: false,
            bytes_transmitted: ValueHistory::new(0, Duration::from_secs(2)),
            bytes_retransmitted: ValueHistory::new(0, Duration::from_secs(2)),
            queue_state: None,
            to_packetize: VecDeque::default(),
            rtp_mode: false,
        }
    }
}

impl MediaInner {
    pub fn from_remote_media_line(l: &MediaLine, index: usize, exts: ExtensionMap) -> Self {
        MediaInner {
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
    pub fn from_add_media(a: AddMedia, exts: ExtensionMap) -> Self {
        let mut media = MediaInner {
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

    pub fn from_app_tmp(mid: Mid, index: usize) -> MediaInner {
        MediaInner {
            mid,
            index,
            app_tmp: true,
            ..Default::default()
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

/// Separate in wait for polonius.
fn get_buffer_tx(
    buffers_tx: &HashMap<Pt, PacketizingBuffer>,
    pt: Pt,
) -> Option<&PacketizingBuffer> {
    buffers_tx.get(&pt)
}

/// Separate in wait for polonius.
fn get_or_create_source_tx<'a>(
    sources_tx: &'a mut Vec<SenderSource>,
    equalize_sources: &'a mut bool,
    ssrc: Ssrc,
) -> &'a mut SenderSource {
    let maybe_idx = sources_tx.iter().position(|r| r.ssrc() == ssrc);

    if let Some(idx) = maybe_idx {
        &mut sources_tx[idx]
    } else {
        *equalize_sources = true;
        sources_tx.push(SenderSource::new(ssrc));
        sources_tx.last_mut().unwrap()
    }
}
