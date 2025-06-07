use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use crate::error::PacketError;
use crate::format::CodecConfig;
use crate::format::PayloadParams;
use crate::io::DATAGRAM_MAX_PACKET_SIZE;
use crate::io::DATAGRAM_MTU_WARN;
use crate::io::MAX_RTP_OVERHEAD;
use crate::media::KeyframeRequestKind;
use crate::media::Media;
use crate::media::MediaKind;
use crate::packet::QueuePriority;
use crate::packet::QueueSnapshot;
use crate::packet::QueueState;
use crate::rtp_::MidRid;
use crate::rtp_::{Bitrate, Descriptions, Extension, ExtensionMap, ExtensionValues, Frequency};
use crate::rtp_::{MediaTime, Mid, NackEntry, ReportList, Rtcp, RtpHeader};
use crate::rtp_::{Pt, Rid, RtcpFb, SenderInfo, SenderReport, Ssrc};
use crate::rtp_::{Sdes, SdesType, MAX_BLANK_PADDING_PAYLOAD_SIZE};
use crate::rtp_::{SeqNo, SRTP_BLOCK_SIZE};
use crate::session::PacketReceipt;
use crate::stats::StatsSnapshot;
use crate::util::value_history::ValueHistory;
use crate::util::{already_happened, not_happening};

use super::rtx_cache::RtxCache;
use super::send_queue::SendQueue;
use super::send_stats::StreamTxStats;
use super::{rr_interval, RtpPacket};

/// The smallest size of padding for which we attempt to use a spurious resend. For padding
/// requests smaller than this we use blank packets instead.
const MIN_SPURIOUS_PADDING_SIZE: usize = 50;

pub const DEFAULT_RTX_CACHE_DURATION: Duration = Duration::from_secs(3);

pub const DEFAULT_RTX_RATIO_CAP: Option<f32> = Some(0.15f32);

/// Outgoing encoded stream.
///
/// A stream is a primary SSRC + optional RTX SSRC.
///
/// This is RTP level API. For sample level API see [`Rtc::writer`][crate::Rtc::writer].
#[derive(Debug)]
pub struct StreamTx {
    /// Unique identifier of the remote encoded stream.
    ssrc: Ssrc,

    /// Identifier of a resend (RTX) stream. If we are doing resends.
    rtx: Option<Ssrc>,

    /// The Media mid and rid this stream belongs to.
    midrid: MidRid,

    /// Set on first handle_timeout.
    kind: Option<MediaKind>,

    /// Set on first handle_timeout.
    cname: Option<String>,

    /// The last main payload clock rate that was sent.
    clock_rate: Option<Frequency>,

    /// If we are doing seq_no ourselves (when writing sample mode).
    seq_no: SeqNo,

    /// If we are using RTX, this is the seq no counter.
    seq_no_rtx: SeqNo,

    /// The last seq_no that we sent, either by increasing seq_no ourselves (media API), or by
    /// direct RTP mode writing.
    last_sent_seq_no: SeqNo,

    /// When we last sent something for this encoded stream, packet or RTCP.
    last_used: Instant,

    /// Last written media + wallclock time.
    rtp_and_wallclock: Option<(u32, Instant)>,

    /// Queue of packets to send.
    ///
    /// The packets here do not have correct sequence numbers, header extension values etc.
    /// They must be updated when we are about to send.
    send_queue: SendQueue,

    /// Whether this sender is to be unpaced in BWE situations.
    ///
    /// Audio defaults to not being paced.
    unpaced: Option<bool>,

    /// Scheduled resends due to NACK or spurious padding.
    resends: VecDeque<Resend>,

    /// Requested padding, that has not been turned into packets yet.
    padding: usize,

    /// Dummy packet for resends. Used between poll_packet and poll_packet_padding
    blank_packet: RtpPacket,

    /// Cache of sent packets to be able to answer to NACKs as well as
    /// sending spurious resends as padding.
    rtx_cache: RtxCache,

    /// Determines retransmitted bytes ratio value to clear queued resends.
    rtx_ratio_cap: Option<f32>,

    /// Last time we produced a SR.
    last_sender_report: Instant,

    /// If we have a pending incoming keyframe request.
    pending_request_keyframe: Option<KeyframeRequestKind>,

    /// If we have a pending incoming remb request.
    pending_request_remb: Option<Bitrate>,

    /// Statistics of outgoing data.
    ///
    /// Stats are use to calculate the rtx ratio also when statistics events are disabled.
    stats: StreamTxStats,

    // downsampled rtx ratio (value, last calculation)
    rtx_ratio: (f32, Instant),

    // The _main_ PT to use for padding. This is main PT, since the poll_packet() loop
    // figures out the param.resend() RTX PT using main.
    pt_for_padding: Option<Pt>,

    /// Whether a receiver report has been received for this SSRC, thus acknowledging
    /// that the receiver has bound the Mid/Rid tuple to the SSRC and no longer
    /// needs to be sent on every packet
    remote_acked_ssrc: bool,
}

impl StreamTx {
    pub(crate) fn new(ssrc: Ssrc, rtx: Option<Ssrc>, midrid: MidRid, enable_stats: bool) -> Self {
        debug!("Create StreamTx for SSRC: {}", ssrc);

        StreamTx {
            ssrc,
            rtx,
            midrid,
            kind: None,
            cname: None,
            clock_rate: None,
            seq_no: SeqNo::default(),
            seq_no_rtx: SeqNo::default(),
            last_sent_seq_no: SeqNo::default(),
            last_used: already_happened(),
            rtp_and_wallclock: None,
            send_queue: SendQueue::new(),
            unpaced: None,
            resends: VecDeque::new(),
            padding: 0,
            blank_packet: RtpPacket::blank(),
            rtx_cache: RtxCache::new(2000, DEFAULT_RTX_CACHE_DURATION),
            rtx_ratio_cap: DEFAULT_RTX_RATIO_CAP,
            last_sender_report: already_happened(),
            pending_request_keyframe: None,
            pending_request_remb: None,
            stats: StreamTxStats::new(enable_stats),
            rtx_ratio: (0.0, already_happened()),
            pt_for_padding: None,
            remote_acked_ssrc: false,
        }
    }

    /// The (primary) SSRC of this encoded stream.
    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    /// The resend (RTX) SSRC of this encoded stream.
    pub fn rtx(&self) -> Option<Ssrc> {
        self.rtx
    }

    /// Mid for this stream.
    ///
    /// In SDP this corresponds to m-line and "Media".
    pub fn mid(&self) -> Mid {
        self.midrid.mid()
    }

    /// Rid for this stream.
    ///
    /// This is used to separate streams with the same [`Mid`] when using simulcast.
    pub fn rid(&self) -> Option<Rid> {
        self.midrid.rid()
    }

    /// Configure the RTX (resend) cache.
    ///
    /// This determines how old incoming NACKs we can reply to.
    ///
    /// `rtx_ratio_cap` determines when to clear queued resends because of too many resends,
    /// i.e. if `tx_sum / (rtx_sum + tx_sum) > rtx_ratio_cap`. `None` disables this functionality
    /// so all queued resends will be sent.
    ///
    /// The default is 1024 packets over 3 seconds and RTX cache drop ratio of 0.15.
    pub fn set_rtx_cache(
        &mut self,
        max_packets: usize,
        max_age: Duration,
        rtx_ratio_cap: Option<f32>,
    ) {
        // Dump old cache to avoid having to deal with resizing logic inside the cache impl.
        self.rtx_cache = RtxCache::new(max_packets, max_age);
        if rtx_ratio_cap.is_some() {
            self.stats
                .bytes_transmitted
                .get_or_insert_with(ValueHistory::default);
            self.stats
                .bytes_retransmitted
                .get_or_insert_with(ValueHistory::default);
        } else {
            self.stats.bytes_transmitted = None;
            self.stats.bytes_retransmitted = None;
        }
        self.rtx_ratio_cap = rtx_ratio_cap;
    }

    /// Set whether this stream is unpaced or not.
    ///
    /// This is only relevant when BWE (Bandwidth Estimation) is enabled. By default, audio is unpaced
    /// thus not held to a steady send rate by the Pacer.
    ///
    /// This overrides the default behavior.
    pub fn set_unpaced(&mut self, unpaced: bool) {
        self.unpaced = Some(unpaced);
    }

    /// Write RTP packet to a send stream.
    ///
    /// The `payload` argument is expected to be only the RTP payload, not the RTP packet header.
    ///
    /// * `pt` Payload type. Declared in the Media this encoded stream belongs to.
    /// * `seq_no` Sequence number to use for this packet.
    /// * `time` Time in whatever the clock rate is for the media in question (normally 90_000 for video
    ///          and 48_000 for audio).
    /// * `wallclock` Real world time that corresponds to the media time in the RTP packet. For an SFU,
    ///               this can be hard to know, since RTP packets typically only contain the media
    ///               time (RTP time). In the simplest SFU setup, the wallclock could simply be the
    ///               arrival time of the incoming RTP data. For better synchronization the SFU
    ///               probably needs to weigh in clock drifts and data provided via the statistics, receiver
    ///               reports etc.
    /// * `marker` Whether to "mark" this packet. This is usually done for the last packet belonging to
    ///            a series of RTP packets constituting the same frame in a video stream.
    /// * `ext_vals` The RTP header extension values to set. The values must be mapped in the session,
    ///              or they will not be set on the RTP packet.
    /// * `nackable` Whether we should respond this packet for incoming NACK from the remote peer. For
    ///              audio this is always false. For temporal encoded video, some packets are discardable
    ///              and this flag should be set accordingly.
    /// * `payload` RTP packet payload, without header.
    #[allow(clippy::too_many_arguments)]
    pub fn write_rtp(
        &mut self,
        pt: Pt,
        seq_no: SeqNo,
        time: u32,
        wallclock: Instant,
        marker: bool,
        ext_vals: ExtensionValues,
        nackable: bool,
        payload: Vec<u8>,
    ) -> Result<(), PacketError> {
        let first_call = self.rtp_and_wallclock.is_none();

        if first_call && seq_no.roc() > 0 {
            // TODO: make it possible to supress this.
            warn!(
                "First SeqNo has non-zero ROC ({}), which needs out-of-band signalling \
                to remote peer",
                seq_no.roc()
            );
        }

        // This 1 in clock frequency will be fixed in poll_output.
        let media_time = MediaTime::from_secs(time as u64);
        self.rtp_and_wallclock = Some((time, wallclock));

        let header = RtpHeader {
            sequence_number: *seq_no as u16,
            marker,
            payload_type: pt,
            timestamp: time,
            ssrc: self.ssrc,
            ext_vals,
            ..Default::default()
        };

        let packet = RtpPacket {
            seq_no,
            time: media_time,
            header,
            payload,
            nackable,
            // The overall idea for str0m is to only drive time forward from handle_input. If we
            // used a "now" argument to write_rtp(), we effectively get a second point that also need
            // to move time forward _for all of Rtc_ – that's too complicated.
            //
            // Instead we set a future timestamp here. When time moves forward in the "regular way",
            // in handle_timeout() we delegate to self.send_queue.handle_timeout() to mark the enqueued
            // timestamp of all packets that are about to be sent.
            timestamp: not_happening(),

            // This is only relevant for incoming RTP packets.
            last_sender_info: None,
        };

        self.send_queue.push(packet);

        Ok(())
    }

    fn padding_enabled(&self) -> bool {
        self.rtx.is_some() && self.pt_for_padding.is_some()
    }

    pub(crate) fn poll_packet(
        &mut self,
        now: Instant,
        exts: &ExtensionMap,
        twcc: Option<&mut u64>,
        params: &[PayloadParams],
        buf: &mut Vec<u8>,
    ) -> Option<PacketReceipt> {
        let mid = self.midrid.mid();
        let rid = self.midrid.rid();
        let ssrc_rtx = self.rtx;
        let remote_acked_ssrc = self.remote_acked_ssrc;

        let (next, is_padding) = if let Some(next) = self.poll_packet_resend(now) {
            (next, false)
        } else if let Some(next) = self.poll_packet_regular(now) {
            (next, false)
        } else if let Some(next) = self.poll_packet_padding(now) {
            (next, true)
        } else {
            return None;
        };

        let pop_send_queue = next.kind == NextPacketKind::Regular;

        // Need the header for the receipt and modifications
        // TODO: Can we remove this?
        let header_ref = &mut next.pkt.header;

        // <https://webrtc.googlesource.com/src/+/refs/heads/main/modules/rtp_rtcp/source/rtp_sender.cc#537>
        // BUNDLE requires that the receiver "bind" the received SSRC to the values
        // in the MID and/or (R)RID header extensions if present. Therefore, the
        // sender can reduce overhead by omitting these header extensions once it
        // knows that the receiver has "bound" the SSRC.
        // <snip>
        // The algorithm here is fairly simple: Always attach a MID and/or RID (if
        // configured) to the outgoing packets until an RTCP receiver report comes
        // back for this SSRC. That feedback indicates the receiver must have
        // received a packet with the SSRC and header extension(s), so the sender
        // then stops attaching the MID and RID.

        // This is true also for RTX.
        if !remote_acked_ssrc {
            header_ref.ext_vals.mid = Some(mid);
            header_ref.ext_vals.rid = rid;
        }

        let pt_main = header_ref.payload_type;

        // The pt in next.pkt is the "main" pt.
        let Some(param) = params.iter().find(|p| p.pt() == pt_main) else {
            // PT does not exist in the connected media.
            warn!("Media is missing PT ({}) used in RTP packet", pt_main);

            // Get rid of this packet we can't send.
            if pop_send_queue {
                self.send_queue.pop(now);
            }

            return None;
        };

        let mut set_pt_for_padding = None;
        let mut set_cr = None;

        let mut header = match next.kind {
            NextPacketKind::Regular => {
                let rtx_possible = param.resend().is_some();

                if rtx_possible {
                    // Remember PT We want to set these directly on `self` here, but can't
                    // because we already have a mutable borrow. We are using pt_main
                    // since the above loop figuring out param needs to be correct also
                    // for the NextPacketKind::Blank case.
                    set_pt_for_padding = Some(pt_main);
                } else {
                    // If the PT we're sending on doesn't have a corresponding RTX PT,
                    // the packet is de-facto not nackable.
                    //
                    // This blocks incoming NACK requests and thus ensures there are no
                    // entries in self.retries without a RTX PT.
                    next.pkt.nackable = false;
                }

                let clock_rate = param.spec().clock_rate;
                set_cr = Some(clock_rate);

                // Modify the cached packet time. This is so write_rtp can use u32 media time without
                // worrying about lengthening or the clock rate.
                let time = MediaTime::new(next.pkt.time.numer(), clock_rate);
                next.pkt.time = time;

                // Modify the original (and also cached) header value.
                header_ref.ext_vals.rid_repair = None;

                header_ref.clone()
            }
            NextPacketKind::Resend(_) | NextPacketKind::Blank(_) => {
                // * For the Resend case, we will not have accepted/cached the packet unless
                //   we have a RTX PT (see logic setting next.pkt.nackable above).
                // * For the Blank case, we will only have produced blank packets if we
                //   got a "real" PTX RT, either via set_pt_for_padding above, or via
                //   the on_first_timeout() further down.
                // Either way, unwrapping this optional _should_ be correct.
                let pt_rtx = param.resend().expect("PT for resend or blank");

                // Clone header to not change the original (cached) header.
                let mut header = header_ref.clone();

                // Update clone of header (to not change the cached value).
                header.payload_type = pt_rtx;
                header.ssrc = ssrc_rtx.expect("Should have RTX SSRC for resends");
                header.sequence_number = *next.seq_no as u16;

                header.ext_vals.rid = None;
                header.ext_vals.rid_repair = rid;

                header
            }
        };

        // These need to match `Extension::is_supported()` so we are sending what we are
        // declaring we support.

        // Absolute Send Time might not be enabled for this m-line.
        if exts.id_of(Extension::AbsoluteSendTime).is_some() {
            header.ext_vals.abs_send_time = Some(now);
        }

        // TWCC might not be enabled for this m-line.
        if let Some(twcc) = twcc {
            header.ext_vals.transport_cc = Some(*twcc as u16);
            *twcc += 1;
        }

        buf.resize(DATAGRAM_MAX_PACKET_SIZE, 0);

        let header_len = header.write_to(buf, exts);
        assert!(header_len % 4 == 0, "RTP header must be multiple of 4");
        header.header_len = header_len;

        let mut body_out = &mut buf[header_len..];

        // For resends, the original seq_no is inserted before the payload.
        let mut original_seq_len = 0;
        if let NextPacketKind::Resend(orig_seq_no) = next.kind {
            original_seq_len = RtpHeader::write_original_sequence_number(body_out, orig_seq_no);
            body_out = &mut body_out[original_seq_len..];
        }

        let pkt = &next.pkt;

        let body_len = match next.kind {
            NextPacketKind::Regular | NextPacketKind::Resend(_) => {
                let body_len = pkt.payload.len();
                body_out[..body_len].copy_from_slice(&pkt.payload);

                // pad for SRTP
                let pad_len = RtpHeader::pad_packet(
                    &mut buf[..],
                    header_len,
                    body_len + original_seq_len,
                    SRTP_BLOCK_SIZE,
                );

                body_len + original_seq_len + pad_len
            }
            NextPacketKind::Blank(len) => {
                let len = RtpHeader::create_padding_packet(
                    &mut buf[..],
                    header_len,
                    len,
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
        {
            let queued_at = match next.kind {
                NextPacketKind::Regular => Some(pkt.timestamp),
                _ => {
                    // TODO: We don't have queued at stats for Resends or blank padding.
                    None
                }
            };

            if let Some(delay) = queued_at.map(|i| now.duration_since(i)) {
                crate::log_stat!("QUEUE_DELAY", header.ssrc, delay.as_secs_f64() * 1000.0);
            }
        }

        let seq_no = next.seq_no;
        if next.kind == NextPacketKind::Regular {
            self.last_sent_seq_no = seq_no;
        }

        self.last_used = now;

        // Padding comes in two forms, "spurious resends" of sent packets where
        // the remote side didn't ask for a resend. The other variant are blank
        // packets, containing nothing but zeroes. Such packets must be sent from
        // _some_ RTX PT. A good pick is the RTX for the PT last used to send
        // regular media data.
        //
        // This is set here due to borrow checker.
        if set_pt_for_padding.is_some() && self.pt_for_padding != set_pt_for_padding {
            self.pt_for_padding = set_pt_for_padding;
        }

        if set_cr.is_some() && self.clock_rate != set_cr {
            self.clock_rate = set_cr;
        }

        if pop_send_queue {
            // poll_packet_regular leaves the packet in the head of the send_queue
            let pkt = self
                .send_queue
                .pop(now)
                .expect("head of send_queue to be there");
            if pkt.nackable {
                self.rtx_cache.cache_sent_packet(pkt, now);
            }
        }

        Some(PacketReceipt {
            header,
            seq_no,
            is_padding,
            payload_size: body_len,
        })
    }

    fn rtx_ratio_downsampled(&mut self, now: Instant) -> f32 {
        assert!(
            self.stats.bytes_transmitted.is_some(),
            "rtx_ratio_cap must be enabled"
        );
        assert!(
            self.stats.bytes_retransmitted.is_some(),
            "rtx_ratio_cap must be enabled"
        );

        let (value, ts) = self.rtx_ratio;
        if now - ts < Duration::from_millis(50) {
            // not worth re-evaluating, return the old value
            return value;
        }

        // bytes stats refer to the last second by default
        self.stats
            .bytes_transmitted
            .as_mut()
            .unwrap()
            .purge_old(now);
        self.stats
            .bytes_retransmitted
            .as_mut()
            .unwrap()
            .purge_old(now);

        let bytes_transmitted = self.stats.bytes_transmitted.as_mut().unwrap().sum();
        let bytes_retransmitted = self.stats.bytes_retransmitted.as_mut().unwrap().sum();
        let ratio = bytes_retransmitted as f32 / (bytes_retransmitted + bytes_transmitted) as f32;
        let ratio = if ratio.is_finite() { ratio } else { 0_f32 };
        self.rtx_ratio = (ratio, now);
        ratio
    }

    fn poll_packet_resend(&mut self, now: Instant) -> Option<NextPacket<'_>> {
        if let Some(ratio_cap) = self.rtx_ratio_cap {
            let ratio = self.rtx_ratio_downsampled(now);

            // If we hit the cap, stop doing resends by clearing those we have queued.
            if ratio > ratio_cap {
                self.resends.clear();
                return None;
            }
        }

        let seq_no = loop {
            let resend = self.resends.pop_front()?;

            let pkt = self.rtx_cache.get_cached_packet_by_seq_no(resend.seq_no);

            // The seq_no could simply be too old to exist in the buffer, in which
            // case we will not do a resend.
            let Some(pkt) = pkt else {
                continue;
            };

            // Cached packets must be nackable. This is ensured before adding the
            // entry to the self.rtx_cache.
            assert!(pkt.nackable);

            break pkt.seq_no;
        };

        // Borrow checker gymnastics.
        let pkt = self.rtx_cache.get_cached_packet_by_seq_no(seq_no).unwrap();

        let len = pkt.payload.len() as u64;
        self.stats.update_packet_counts(len, true);
        if let Some(h) = &mut self.stats.bytes_retransmitted {
            h.push(now, len);
        }

        let seq_no = self.seq_no_rtx.inc();

        let orig_seq_no = pkt.seq_no;

        Some(NextPacket {
            kind: NextPacketKind::Resend(orig_seq_no),
            seq_no,
            pkt,
        })
    }

    fn poll_packet_regular(&mut self, now: Instant) -> Option<NextPacket<'_>> {
        // exit via ? here is ok since that means there is nothing to send.
        // The packet remains in the head of the send queue until we
        // finish poll_packet, at which point we move it to the cache.
        let pkt = self.send_queue.peek()?;

        pkt.timestamp = now;

        let len = pkt.payload.len() as u64;
        self.stats.update_packet_counts(len, false);
        if let Some(h) = &mut self.stats.bytes_transmitted {
            h.push(now, len)
        }

        let seq_no = pkt.seq_no;

        Some(NextPacket {
            kind: NextPacketKind::Regular,
            seq_no,
            pkt,
        })
    }

    fn poll_packet_padding(&mut self, _now: Instant) -> Option<NextPacket> {
        if !self.padding_enabled() {
            self.padding = 0;
            return None;
        }

        if self.padding == 0 {
            return None;
        }

        #[allow(clippy::unnecessary_operation)]
        'outer: {
            if self.padding > MIN_SPURIOUS_PADDING_SIZE {
                // Find a historic packet that is smaller than this max size. The max size
                // is a headroom since we can accept slightly larger padding than asked for.
                let max_size = (self.padding * 2).min(DATAGRAM_MTU_WARN - MAX_RTP_OVERHEAD);

                let Some(pkt) = self.rtx_cache.get_cached_packet_smaller_than(max_size) else {
                    // Couldn't find spurious packet, try a blank packet instead.
                    break 'outer;
                };

                let orig_seq_no = pkt.seq_no;
                let seq_no = self.seq_no_rtx.inc();

                self.padding = self.padding.saturating_sub(pkt.payload.len());

                return Some(NextPacket {
                    kind: NextPacketKind::Resend(orig_seq_no),
                    seq_no,
                    pkt,
                });
            }
        };

        let seq_no = self.seq_no_rtx.inc();

        let pkt = &mut self.blank_packet;
        pkt.seq_no = seq_no;
        // Unwrap here is correct because self.padding_enabled() above checks the we got the PT set.
        pkt.header.payload_type = self.pt_for_padding.unwrap();

        let len = self
            .padding
            .clamp(SRTP_BLOCK_SIZE, MAX_BLANK_PADDING_PAYLOAD_SIZE);
        assert!(len <= 255); // should fit in a byte

        self.padding = self.padding.saturating_sub(len);

        Some(NextPacket {
            kind: NextPacketKind::Blank(len as u8),
            seq_no,
            pkt,
        })
    }

    pub(crate) fn sender_report_at(&self) -> Instant {
        let Some(kind) = self.kind else {
            // First handle_timeout sets the kind. No sender report until then.
            return not_happening();
        };
        self.last_sender_report + rr_interval(kind.is_audio())
    }

    pub(crate) fn poll_keyframe_request(&mut self) -> Option<KeyframeRequestKind> {
        self.pending_request_keyframe.take()
    }

    pub(crate) fn poll_remb_request(&mut self) -> Option<Bitrate> {
        self.pending_request_remb.take()
    }

    pub(crate) fn handle_rtcp(&mut self, now: Instant, fb: RtcpFb) {
        use RtcpFb::*;
        match fb {
            ReceptionReport(r) => {
                // Receiver has bound MidRid to SSRC
                self.remote_acked_ssrc = true;
                self.stats.update_with_rr(now, self.last_sent_seq_no, r)
            }
            Nack(_, list) => {
                self.stats.increase_nacks();
                let entries = list.into_iter();
                self.handle_nack(entries, now);
            }
            Pli(_) => {
                self.stats.increase_plis();
                self.pending_request_keyframe = Some(KeyframeRequestKind::Pli);
            }
            Fir(_) => {
                self.stats.increase_firs();
                self.pending_request_keyframe = Some(KeyframeRequestKind::Fir);
            }
            Remb(r) => {
                self.pending_request_remb = Some(Bitrate::from(r.bitrate as f64));
            }
            Twcc(_) => unreachable!("TWCC should be handled on session level"),
            _ => {}
        }
    }

    pub(crate) fn handle_nack(
        &mut self,
        entries: impl Iterator<Item = NackEntry>,
        now: Instant,
    ) -> Option<()> {
        // Turning NackEntry into SeqNo we need to know a SeqNo "close by" to lengthen the 16 bit
        // sequence number into the 64 bit we have in SeqNo.
        let seq_no = self.rtx_cache.last_cached_seq_no()?;
        let iter = entries.flat_map(|n| n.into_iter(seq_no));

        // Schedule all resends. They will be handled on next poll_packet
        for seq_no in iter {
            let Some(packet) = self.rtx_cache.get_cached_packet_by_seq_no(seq_no) else {
                // Packet was not available in RTX cache, it has probably expired.
                continue;
            };

            let resend = Resend {
                seq_no,
                queued_at: now,
                payload_size: packet.payload.len(),
            };
            self.resends.push_back(resend);
        }

        Some(())
    }

    pub(crate) fn need_sr(&self, now: Instant) -> bool {
        now >= self.sender_report_at()
    }

    pub(crate) fn create_sr_and_update(&mut self, now: Instant, feedback: &mut VecDeque<Rtcp>) {
        let sr = self.create_sender_report(now);

        trace!("Created feedback SR: {:?}", sr);
        feedback.push_back(Rtcp::SenderReport(sr));

        if let Some(ds) = self.create_sdes() {
            feedback.push_back(Rtcp::SourceDescription(ds));
        }

        // Update timestamp to move time when next is created.
        self.last_sender_report = now;
    }

    fn create_sender_report(&self, now: Instant) -> SenderReport {
        SenderReport {
            sender_info: self.sender_info(now),
            reports: ReportList::new(),
        }
    }

    fn create_sdes(&self) -> Option<Descriptions> {
        // CNAME is set on first handle_timeout. No SDES before that.
        let cname = self.cname.as_ref()?;
        let mut s = Sdes {
            ssrc: self.ssrc,
            values: ReportList::new(),
        };
        s.values.push((SdesType::CNAME, cname.to_string()));

        let mut d = Descriptions {
            reports: Box::new(ReportList::new()),
        };
        d.reports.push(s);

        Some(d)
    }

    fn sender_info(&self, now: Instant) -> SenderInfo {
        let rtp_time = self.current_rtp_time(now).unwrap_or(MediaTime::ZERO);

        SenderInfo {
            ssrc: self.ssrc,
            ntp_time: now,
            rtp_time,
            sender_packet_count: self.stats.packets as u32,
            sender_octet_count: self.stats.bytes as u32,
        }
    }

    fn current_rtp_time(&self, now: Instant) -> Option<MediaTime> {
        // This is the RTP time and the wallclock from the last written media.
        // We use that as an offset to current time (now), to calculate the
        // current RTP time.
        let (t_u32, w) = self.rtp_and_wallclock?;

        let clock_rate = self.clock_rate?;
        let t = MediaTime::new(t_u32 as u64, clock_rate);

        // Wallclock needs to be in the past.
        if w > now {
            let delta = w - now;
            debug!("write_rtp wallclock is in the future: {:?}", delta);
            return None;
        }
        let offset = now - w;

        // This might be in the wrong base.
        let rtp_time = t + offset.into();

        Some(rtp_time.rebase(clock_rate))
    }

    pub(crate) fn next_seq_no(&mut self) -> SeqNo {
        self.seq_no.inc()
    }

    pub(crate) fn last_packet(&self) -> Option<&[u8]> {
        if self.send_queue.is_empty() {
            self.rtx_cache.last_packet()
        } else {
            self.send_queue.last().map(|q| q.payload.as_ref())
        }
    }

    pub(crate) fn visit_stats(&mut self, snapshot: &mut StatsSnapshot, now: Instant) {
        self.stats.fill(snapshot, self.midrid, now);
    }

    pub(crate) fn queue_state(&mut self, now: Instant) -> QueueState {
        // The unpaced flag is set to a default value on first handle_timeout. The
        // default is to not pace audio. We unwrap default to "true" here to not
        // apply any pacing until we know what kind of content we are sending.
        let unpaced = self.unpaced.unwrap_or(true);

        // It's only possible to use this sender for padding if RTX is enabled and
        // we know a PT to use for it.
        let use_for_padding = self.padding_enabled();

        let mut snapshot = self.send_queue.snapshot(now);

        if let Some(snapshot_resend) = self.queue_state_resend(now) {
            snapshot.merge(&snapshot_resend);
        }

        if let Some(snapshot_padding) = self.queue_state_padding(now) {
            snapshot.merge(&snapshot_padding);
        }

        QueueState {
            midrid: self.midrid,
            unpaced,
            use_for_padding,
            snapshot,
        }
    }

    fn queue_state_resend(&self, now: Instant) -> Option<QueueSnapshot> {
        if self.resends.is_empty() {
            return None;
        }

        // Outstanding resends
        let mut snapshot = self
            .resends
            .iter()
            .fold(QueueSnapshot::default(), |mut snapshot, r| {
                snapshot.total_queue_time_origin += now.duration_since(r.queued_at);
                snapshot.size += r.payload_size;
                snapshot.packet_count += 1;
                snapshot.first_unsent = snapshot
                    .first_unsent
                    .map(|i| i.min(r.queued_at))
                    .or(Some(r.queued_at));

                snapshot
            });
        snapshot.created_at = now;
        snapshot.update_priority(QueuePriority::Media);

        Some(snapshot)
    }

    fn queue_state_padding(&self, now: Instant) -> Option<QueueSnapshot> {
        if self.padding == 0 {
            return None;
        }

        // TODO: Be more scientific about these factors.
        const AVERAGE_PADDING_PACKET_SIZE: usize = 800;
        const FAKE_PADDING_DURATION_MILLIS: usize = 5;

        let fake_packets = self.padding / AVERAGE_PADDING_PACKET_SIZE;
        let fake_millis = fake_packets * FAKE_PADDING_DURATION_MILLIS;
        let fake_duration = Duration::from_millis(fake_millis as u64);

        Some(QueueSnapshot {
            created_at: now,
            size: self.padding,
            packet_count: fake_packets as u32,
            total_queue_time_origin: fake_duration,
            priority: QueuePriority::Padding,
            ..Default::default()
        })
    }

    pub(crate) fn generate_padding(&mut self, padding: usize) {
        if !self.padding_enabled() {
            return;
        }
        self.padding += padding;
    }

    pub(crate) fn need_timeout(&self) -> bool {
        self.send_queue.need_timeout()
    }

    pub(crate) fn handle_timeout<'a>(
        &mut self,
        now: Instant,
        get_media: impl FnOnce() -> (&'a Media, &'a CodecConfig),
    ) {
        // If kind is None, this is the first time we ever get a handle_timeout.
        if self.kind.is_none() {
            let (media, config) = get_media();
            self.on_first_timeout(media, config);
        }

        self.send_queue.handle_timeout(now);
    }

    fn on_first_timeout(&mut self, media: &Media, config: &CodecConfig) {
        // Always set on first timeout.
        self.kind = Some(media.kind());
        self.cname = Some(media.cname().to_string());

        // Set on first timeout, if not set already by configuration.
        if self.unpaced.is_none() {
            // Default audio to be unpaced.
            self.unpaced = Some(media.kind().is_audio());
        }

        // To allow for sending padding on a newly created StreamTx, before any regular
        // packet has been sent, we need any main PT that has associated RTX. This is
        // later be overwritten when we send the first regular packet.
        if self.rtx.is_some() && self.pt_for_padding.is_none() {
            if let Some(pt) = media.first_pt_with_rtx(config) {
                trace!(
                    "StreamTx {:?} PT {} before first regular packet",
                    self.midrid,
                    pt
                );
                self.pt_for_padding = Some(pt);

                // Setting the pt_for_rtx should enable RTX.
                assert!(self.padding_enabled());
            }
        }
    }

    pub(crate) fn reset_buffers(&mut self) {
        self.send_queue.clear();
        self.rtx_cache.clear();
        self.resends.clear();
        self.padding = 0;
    }

    /// Reset this stream to use a new SSRC and optionally a new RTX SSRC.
    ///
    /// This updates the SSRCs and resets all relevant internal fields.
    pub(crate) fn reset_ssrc(&mut self, new_ssrc: Ssrc, new_rtx: Option<Ssrc>) {
        // Update the SSRC and RTX
        self.ssrc = new_ssrc;
        self.rtx = new_rtx;

        // Reset sequence numbers
        self.seq_no = SeqNo::default();
        self.seq_no_rtx = SeqNo::default();

        // Reset timing related fields
        self.last_used = already_happened();
        self.rtp_and_wallclock = None;
        self.last_sender_report = already_happened();

        // Reset blank packet's SSRC
        self.blank_packet.header.ssrc = new_ssrc;

        // Clear any pending requests
        self.pending_request_keyframe = None;
        self.pending_request_remb = None;

        // Reset all statistics - preserve whether stats tracking is enabled
        let stats_enabled = self.stats.bytes_transmitted.is_some();
        self.stats = StreamTxStats::new(stats_enabled);
        self.rtx_ratio = (0.0, already_happened());
        self.remote_acked_ssrc = false;

        // Clear all buffers
        self.reset_buffers();
    }

    pub(crate) fn is_midrid(&self, midrid: MidRid) -> bool {
        midrid.special_equals(&self.midrid)
    }
}

struct NextPacket<'a> {
    kind: NextPacketKind,
    seq_no: SeqNo,
    pkt: &'a mut RtpPacket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextPacketKind {
    Regular,
    Resend(SeqNo),
    Blank(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resend {
    seq_no: SeqNo,
    queued_at: Instant,
    payload_size: usize,
}
