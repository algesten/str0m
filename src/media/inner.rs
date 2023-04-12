use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::change::AddMedia;
use crate::format::Codec;
use crate::packet::ToSendMeta;
use crate::rtp::PacketizedId;
pub use crate::rtp::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid, Ssrc};

use crate::io::{Id, DATAGRAM_MTU};
use crate::packet::{DepacketizingBuffer, MediaKind, Packetized};
use crate::packet::{PacketizedMeta, PacketizingBuffer};
use crate::rtp::{ExtensionMap, Fir, FirEntry, NackEntry, Pli, Rtcp};
use crate::rtp::{RtcpFb, RtpHeader, SdesType};
use crate::rtp::{SeqNo, MAX_PADDING_PACKET_SIZE, SRTP_BLOCK_SIZE, SRTP_OVERHEAD};
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

    /// Whether we are running in RTP-mode.
    pub(crate) rtp_mode: bool,

    /// ToSendMeta from writing to a packetizing buffer.
    ///
    /// These are moved into the pacer on Session::handle_timeout().
    to_send_meta: VecDeque<ToSendMeta>,
}

struct NextPacket<'a> {
    pt: Pt,
    ssrc: Ssrc,
    seq_no: SeqNo,
    body: NextPacketBody<'a>,
}

enum NextPacketBody<'a> {
    /// A regular packetized packet
    Regular { pkt: &'a Packetized },
    /// A resend of a previously sent packet
    Resend {
        pkt: &'a Packetized,
        orig_seq_no: Option<SeqNo>,
    },
    /// An empty padding packet to be generated.
    Padding { len: u8 },
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
        fucking_counter: &mut u64,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: &[u8],
        rid: Option<Rid>,
        ext_vals: ExtensionValues,
        rtp_mode_header: Option<RtpHeader>,
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
        let buf = self.buffers_tx.entry(pt).or_insert_with(|| {
            let max_retain = if is_audio { 4096 } else { 2048 };
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

        if self.rtp_mode {
            let rtp_header = rtp_mode_header.expect("rtp header in rtp mode");
            let v = buf.push_rtp_packet(fucking_counter, data.to_vec(), meta, rtp_header);
            self.to_send_meta.push_back(v);
        } else {
            const RTP_SIZE: usize = DATAGRAM_MTU - SRTP_OVERHEAD;
            // align to SRTP block size to minimize padding needs
            const MTU: usize = RTP_SIZE - RTP_SIZE % SRTP_BLOCK_SIZE;

            let v = match buf.push_sample(fucking_counter, &data, meta, MTU) {
                Ok(v) => v,
                Err(e) => {
                    return Err(RtcError::Packet(self.mid, pt, e));
                }
            };
            self.to_send_meta.extend(v);
        }

        Ok(())
    }

    pub(crate) fn write_rtp(
        &mut self,
        fucking_counter: &mut u64,
        pt: Pt,
        wallclock: Instant,
        packet: &[u8],
        exts: &ExtensionMap,
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
            fucking_counter,
            pt,
            wallclock,
            rtp_time,
            packet,
            rid,
            header.ext_vals,
            Some(header),
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
        pad_size: Option<usize>,
        buf: &mut Vec<u8>,
    ) -> Option<(RtpHeader, SeqNo, Option<PacketizedId>)> {
        let mid = self.mid;

        let next = if let Some(next) = self.poll_packet_resend_to_cap(now) {
            next
        } else if let Some(next) = self.poll_packet_regular(now) {
            next
        } else if let Some(next) = self.poll_packet_padding(now, pad_size) {
            next
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

        let mut packet_id = None;

        let body_len = match next.body {
            NextPacketBody::Regular { pkt } | NextPacketBody::Resend { pkt, .. } => {
                let body_len = pkt.data.len();
                body_out[..body_len].copy_from_slice(&pkt.data);

                packet_id = Some(pkt.id);

                // pad for SRTP
                let pad_len = RtpHeader::pad_packet(
                    &mut buf[..],
                    header_len,
                    body_len + original_seq_len,
                    SRTP_BLOCK_SIZE,
                );

                body_len + original_seq_len + pad_len
            }
            NextPacketBody::Padding { len } => {
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

        #[cfg(feature = "_internal_dont_uselog_stats")]
        if let Some(delay) = next.body.queued_at().map(|i| now.duration_since(i)) {
            crate::log_stat!("QUEUE_DELAY", header.ssrc, delay.as_millis());
        }

        Some((header, next.seq_no, packet_id))
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
            return None;
        }

        self.poll_packet_resend(now, false)
    }

    fn poll_packet_resend(&mut self, now: Instant, is_padding: bool) -> Option<NextPacket<'_>> {
        let (resend, source) = loop {
            let resend = self.resends.pop_front()?;

            // If there is no buffer for this resend, we return None. This is
            // a weird situation though, since it means the other side sent a nack for
            // an SSRC that matched this Media, but didn't match a buffer_tx.
            let buffer = self.buffers_tx.values().find(|p| p.has_ssrc(resend.ssrc))?;

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

        // get_and_mark_as_unaccounted() requires a mut reference to buffer, which we can't do in the
        // above loop (waiting for polonius). The solution is to look the buffer up again after the loop.
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
        let (pt, pkt) = next_send_buffer(&mut self.buffers_tx, now)?;

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
        pkt.seq_no = Some(seq_no);

        Some(NextPacket {
            pt,
            seq_no,
            ssrc: pkt.meta.ssrc,
            body: NextPacketBody::Regular { pkt },
        })
    }

    fn poll_packet_padding(&mut self, now: Instant, pad_size: Option<usize>) -> Option<NextPacket> {
        // We only produce padding packet if there is an asked for padding size.
        let pad_size = pad_size?;

        // Only do padding packets if we are using RTX, or we will increase the seq_no
        // on the main SSRC for filler stuff.
        if !self.has_tx_rtx() {
            return None;
        }

        // TODO: This function should be split into two halves, but because of the borrow checker
        // it's hard to construct.

        // This first scope tries to send a spurious (unasked for) resend of a packet already sent.
        {
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

                    // Piggy-back on regular resends.
                    // We should never add padding as long as there are resends.
                    assert!(self.resends.is_empty());
                    self.resends.push_front(Resend {
                        pt,
                        ssrc: packet.meta.ssrc,
                        seq_no,
                        queued_at: now,
                    });

                    return self.poll_packet_resend(now, true);
                }
            }
        }

        // This second scope sends an empty padding packet. This is a fallback strategy if we fail
        // to find a suitable rtx packet above.
        // NB: If we cannot generate padding here for some reason we'll get stuck forever.
        {
            let pt = *self.buffers_tx.keys().next()?;
            let pt_rtx = pt_rtx(&self.params, pt)?;
            let ssrc_rtx = self
                .sources_tx
                .iter()
                .find(|s| s.is_rtx())
                .map(|s| s.ssrc())
                .expect("at least one rtx source");

            let padding = pad_size.max(MAX_PADDING_PACKET_SIZE);

            let seq_no = self
                .get_or_create_source_tx(ssrc_rtx)
                .next_seq_no(now, None);

            Some(NextPacket {
                pt: pt_rtx,
                ssrc: ssrc_rtx,
                seq_no,
                body: NextPacketBody::Padding { len: padding as u8 },
            })
        }
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
        let maybe_idx = self.sources_tx.iter().position(|r| r.ssrc() == ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_tx[idx]
        } else {
            self.equalize_sources = true;
            self.sources_tx.push(SenderSource::new(ssrc));
            self.sources_tx.last_mut().unwrap()
        }
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

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        if self.to_send_meta.is_empty() {
            None
        } else {
            Some(already_happened())
        }
    }

    pub fn take_to_send_meta(&mut self, now: Instant) -> impl Iterator<Item = ToSendMeta> + '_ {
        let mid = self.mid;
        self.to_send_meta.drain(..).map(move |mut m| {
            // Add on values from this level
            m.mid = mid;
            m.since = now;

            m
        })
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
                        network_time: dep.network_time(),
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
        let (pt, buffer) = self.buffers_tx.iter_mut().find(|(_, p)| p.has_ssrc(ssrc))?;

        // Turning NackEntry into SeqNo we need to know a SeqNo "close by" to lengthen the 16 bit
        // sequence number into the 64 bit we have in SeqNo.
        let seq_no = buffer.first_seq_no()?;
        let iter = entries.flat_map(|n| n.into_iter(seq_no));

        // Schedule all resends. They will be handled on next poll_packet
        for seq_no in iter {
            let resend = Resend {
                ssrc,
                pt: *pt,
                seq_no,
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

    /// Test if any source_tx in this channel has rtx.
    fn has_tx_rtx(&self) -> bool {
        self.sources_tx.iter().any(|s| s.is_rtx())
    }
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
            Padding { .. } => 0,
        }
    }

    fn ext_vals(&self) -> ExtensionValues {
        use NextPacketBody::*;
        match self {
            Regular { pkt } => pkt.meta.ext_vals,
            Resend { pkt, .. } => pkt.meta.ext_vals,
            Padding { .. } => ExtensionValues::default(),
        }
    }

    fn marker(&self) -> bool {
        use NextPacketBody::*;
        match self {
            Regular { pkt } => pkt.marker,
            Resend { pkt, .. } => pkt.marker,
            Padding { .. } => false,
        }
    }

    fn orig_seq_no(&self) -> Option<SeqNo> {
        use NextPacketBody::*;
        match self {
            Regular { .. } => None,
            Resend { orig_seq_no, .. } => *orig_seq_no,
            Padding { .. } => None,
        }
    }

    #[cfg(feature = "_internal_dont_use_log_stats")]
    fn queued_at(&self) -> Option<Instant> {
        use NextPacketBody::*;
        match self {
            Regular { pkt } => Some(pkt.meta.queued_at),
            // TODO: Accurate queued_at for resends
            Resend { .. } => None,
            Padding { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resend {
    pub ssrc: Ssrc,
    pub pt: Pt,
    pub seq_no: SeqNo,
    pub queued_at: Instant,
}

fn next_send_buffer(
    buffers_tx: &mut HashMap<Pt, PacketizingBuffer>,
    now: Instant,
) -> Option<(Pt, &mut Packetized)> {
    for (pt, buf) in buffers_tx {
        if let Some(pkt) = buf.poll_next(now) {
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
            need_open_event: true,
            need_changed_event: false,
            keyframe_request_rx: None,
            keyframe_request_tx: None,
            simulcast: None,
            equalize_sources: false,
            enable_nack: false,
            bytes_transmitted: ValueHistory::new(0, Duration::from_secs(2)),
            bytes_retransmitted: ValueHistory::new(0, Duration::from_secs(2)),
            rtp_mode: false,
            to_send_meta: VecDeque::default(),
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
