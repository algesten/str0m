use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use crate::format::PayloadParams;
use crate::media::KeyframeRequestKind;
use crate::rtp_::{extend_u16, InstantExt, ReportList, Rtcp};
use crate::rtp_::{ExtensionMap, ReceptionReport, RtpHeader};
use crate::rtp_::{ExtensionValues, MediaTime, Mid, NackEntry};
use crate::rtp_::{Pt, Rid, RtcpFb, SenderInfo, SenderReport, Ssrc};
use crate::rtp_::{SeqNo, SRTP_BLOCK_SIZE};
use crate::session::PacketReceipt;
use crate::stats::MediaEgressStats;
use crate::stats::StatsSnapshot;
use crate::util::value_history::ValueHistory;
use crate::util::{already_happened, calculate_rtt_ms};
use crate::RtcError;

use super::rtx_cache::RtxCache;
use super::{rr_interval, RtpPacket};

/// Outgoing encoded stream.
#[derive(Debug)]
pub struct StreamTx {
    /// Unique identifier of the remote encoded stream.
    ssrc: Ssrc,

    /// Identifier of a resend (RTX) stream. If we are doing resends.
    rtx: Option<Ssrc>,

    /// The Media mid this stream belongs to.
    mid: Mid,

    /// The rid that might be used for this stream.
    rid: Option<Rid>,

    /// Payload type for resends. This is set locally to "remember" which
    /// RTX PT is used for the current sending PT.
    rtx_pt: Option<Pt>,

    /// If we are doing seq_no ourselves (when writing sample mode).
    seq_no: SeqNo,

    /// If we are using RTX, this is the seq no counter.
    seq_no_rtx: SeqNo,

    /// When we last sent something for this encoded stream, packet or RTCP.
    last_used: Instant,

    /// Last written media + wallclock time.
    rtp_and_wallclock: Option<(MediaTime, Instant)>,

    /// Queue of packets to send.
    ///
    /// The packets here do not have correct sequence numbers, header extension values etc.
    /// They must be updated when we are about to send.
    send_queue: VecDeque<RtpPacket>,

    /// Scheduled resends due to NACK or spurious padding.
    resends: VecDeque<Resend>,

    /// Cache of sent packets to be able to answer to NACKs as well as
    /// sending spurious resends as padding.
    rtx_cache: RtxCache,

    /// Last time we produced a SR.
    last_sender_report: Instant,

    /// If we have a pending incoming keyframe request.
    pending_request_keyframe: Option<KeyframeRequestKind>,

    /// Statistics of outgoing data.
    stats: StreamTxStats,
}

/// Holder of stats.
#[derive(Debug, Default)]
pub(crate) struct StreamTxStats {
    bytes: u64,
    bytes_resent: u64,
    packets: u64,
    packets_resent: u64,
    firs: u64,
    plis: u64,
    nacks: u64,
    rtt: Option<f32>,
    losses: Vec<(u64, f32)>,
    bytes_transmitted: ValueHistory<u64>,
    bytes_retransmitted: ValueHistory<u64>,
}

impl StreamTx {
    pub(crate) fn new(ssrc: Ssrc, rtx: Option<Ssrc>, mid: Mid, rid: Option<Rid>) -> Self {
        // https://www.rfc-editor.org/rfc/rfc3550#page-13
        // The initial value of the sequence number SHOULD be random (unpredictable)
        // to make known-plaintext attacks on encryption more difficult
        let seq_no = (rand::random::<u16>() as u64).into();
        let seq_no_rtx = (rand::random::<u16>() as u64).into();

        debug!("Create StreamTx for SSRC: {}", ssrc);

        StreamTx {
            ssrc,
            rtx,
            mid,
            rid,
            rtx_pt: None,
            seq_no,
            seq_no_rtx,
            last_used: already_happened(),
            rtp_and_wallclock: None,
            send_queue: VecDeque::new(),
            resends: VecDeque::new(),
            rtx_cache: RtxCache::new(1024, Duration::from_secs(3), false),
            last_sender_report: already_happened(),
            pending_request_keyframe: None,
            stats: StreamTxStats::default(),
        }
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    pub fn rtx(&self) -> Option<Ssrc> {
        self.rtx
    }

    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub fn rid(&self) -> Option<Rid> {
        self.rid
    }

    /// Configure the RTX (resend) cache.
    ///
    /// This determines how old incoming NACKs we can reply to.
    ///
    /// The default is 1024 packets over 3 seconds.
    pub fn set_rtx_cache(&mut self, max_packets: usize, max_age: Duration) {
        // Dump old cache to avoid having to deal with resizing logic inside the cache impl.
        self.rtx_cache = RtxCache::new(max_packets, max_age, false);
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
    ///            a series of RTP packets consituting the same frame in a video stream.
    /// * `ext_vals` The RTP header extension values to set. The values must be mapped in the session,
    ///              or they will not be set on the RTP packet.
    /// * `nackable` Whether we should respond this packet for incoming NACK from the remote peer. For
    ///              audio this is always false. For temporal encoded video, some packets are discardable
    ///              and this flag should be set accordingly.
    /// * `payload` RTP packet payload, without header.
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
    ) -> Result<(), RtcError> {
        //
        // This 1 in clock frequency will be fixed in poll_output.
        let media_time = MediaTime::new(time as i64, 1);
        self.rtp_and_wallclock = Some((media_time, wallclock));

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
            pt,
            time: media_time,
            header,
            payload: payload.into(),
            nackable,
            timestamp: already_happened(), // Updated on first ever poll_output.
        };

        self.send_queue.push_back(packet);

        Ok(())
    }

    pub(crate) fn poll_packet(
        &mut self,
        now: Instant,
        exts: &ExtensionMap,
        twcc: &mut u64,
        params: &[PayloadParams],
        buf: &mut Vec<u8>,
    ) -> Option<PacketReceipt> {
        let mid = self.mid;
        let rid = self.rid;

        let (next, is_padding) = if let Some(next) = self.poll_packet_resend(now, false) {
            (next, false)
        } else if let Some(next) = self.poll_packet_regular(now) {
            (next, false)
        // } else if let Some(next) = self.poll_packet_padding(now) {
        //     (next, true)
        } else {
            return None;
        };

        let header = &mut next.pkt.header;

        // We can fill out as many values we want here, only the negotiated ones will
        // be used when writing the RTP packet.
        //
        // These need to match `Extension::is_supported()` so we are sending what we are
        // declaring we support.
        header.ext_vals.abs_send_time = Some(MediaTime::new_ntp_time(now));
        header.ext_vals.mid = Some(mid);
        header.ext_vals.transport_cc = Some(*twcc as u16);
        *twcc += 1;

        // The pt in next.pkt is the "main" pt.
        let Some(param) = params.iter().find(|p| p.pt() == next.pkt.pt) else {
            // PT does not exist in the connected media.
            warn!("Media is missing PT ({}) used in RTP packet", next.pkt.pt);
            return None;
        };

        // Now we know the parameters, update the denominator of the MediaTime.
        next.pkt.time = MediaTime::new(next.pkt.time.numer(), param.spec().clock_rate as i64);

        match next.kind {
            NextPacketKind::Regular => {
                let pt = param.pt();
                header.payload_type = pt;
                next.pkt.pt = pt;

                header.ext_vals.rid = rid;
                header.ext_vals.rid_repair = None;
            }
            NextPacketKind::Resend(_) | NextPacketKind::Blank(_) => {
                let pt_rtx = param.resend().expect("pt_rtx resend/blank");
                header.payload_type = pt_rtx;
                next.pkt.pt = pt_rtx;

                header.ext_vals.rid = None;
                header.ext_vals.rid_repair = rid;
            }
        }

        buf.resize(2000, 0);

        let header_len = header.write_to(buf, exts);
        assert!(header_len % 4 == 0, "RTP header must be multiple of 4");
        header.header_len = header_len;

        // Need the header for the receipt.
        // TODO: Can we remove this?
        let header = header.clone();

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

        let seq_no = next.seq_no;
        self.last_used = now;

        Some(PacketReceipt {
            header,
            seq_no,
            is_padding,
            payload_size: body_len,
        })
    }

    fn poll_packet_resend(&mut self, now: Instant, is_padding: bool) -> Option<NextPacket<'_>> {
        if self.rtx.is_none() || self.rtx_pt.is_none() {
            // We're not doing resends for non-RTX.
            return None;
        }

        let seq_no = loop {
            let resend = self.resends.pop_front()?;

            let pkt = self.rtx_cache.get_cached_packet_by_seq_no(resend.seq_no);

            // The seq_no could simply be too old to exist in the buffer, in which
            // case we will not do a resend.
            let Some(pkt) = pkt else {
                continue;
            };

            if !pkt.nackable {
                trace!("SSRC {} resend {} not nackable", self.ssrc, pkt.seq_no);
            }

            break pkt.seq_no;
        };

        // Borrow checker gymnastics.
        let pkt = self.rtx_cache.get_cached_packet_by_seq_no(seq_no).unwrap();

        if !is_padding {
            let len = pkt.payload.len() as u64;
            self.stats.update_packet_counts(len, true);
            self.stats.bytes_retransmitted.push(now, len);
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
        let mut pkt = self.send_queue.pop_front()?;

        pkt.timestamp = now;

        let len = pkt.payload.len() as u64;
        self.stats.update_packet_counts(len, false);
        self.stats.bytes_transmitted.push(now, len);

        let seq_no = pkt.seq_no;

        self.rtx_cache.cache_sent_packet(pkt, now);
        let pkt = self.rtx_cache.get_cached_packet_by_seq_no(seq_no).unwrap(); // we just cached it

        Some(NextPacket {
            kind: NextPacketKind::Regular,
            seq_no,
            pkt,
        })
    }

    // fn poll_packet_padding(&mut self, now: Instant) -> Option<NextPacket> {
    //     loop {
    //         let padding = self.padding.pop_front()?;

    //         // Force recaching since padding changed.
    //         self.queue_state = None;

    //         match padding {
    //             Padding::Blank { ssrc, pt, size, .. } => {
    //                 let source_tx = get_or_create_source_tx(
    //                     &mut self.sources_tx,
    //                     &mut self.equalize_sources,
    //                     ssrc,
    //                 );
    //                 let seq_no = source_tx.next_seq_no(now, None);

    //                 trace!(
    //                     "Generating blank padding packet of size {size} on {ssrc} with pt: {pt}"
    //                 );
    //                 return Some(NextPacket {
    //                     pt,
    //                     ssrc,
    //                     seq_no,
    //                     body: NextPacketBody::Blank { len: size as u8 },
    //                 });
    //             }
    //             Padding::Spurious(resend) => {
    //                 // If there is no buffer for this padding, we return None. This is
    //                 // a weird situation though, since it means we queued padding for a buffer we don't
    //                 // have.
    //                 let Some(buffer) = self
    //                     .buffers_tx
    //                     .values()
    //                     .find(|p| p.ssrc() == padding.ssrc()) else {
    //                         // This can happen for example case buffers were
    //                         // cleared (i.e. a change of media direction)
    //                         continue;
    //                     };

    //                 let pkt = buffer.get(resend.seq_no);

    //                 // The seq_no could simply be too old to exist in the buffer, in which
    //                 // case we will not do a resend.
    //                 let Some(pkt) = pkt else {
    //                     continue;
    //                 };

    //                 // The send source, to get a contiguous seq_no for the resend.
    //                 // Audio should not be resent, so this also gates whether we are doing resends at all.
    //                 let source = match get_source_tx(&mut self.sources_tx, pkt.meta.rid, true) {
    //                     Some(v) => v,
    //                     None => continue,
    //                 };

    //                 let seq_no = source.next_seq_no(now, None);

    //                 // The resend ssrc. This would correspond to the RTX PT for video.
    //                 let ssrc_rtx = source.ssrc();

    //                 let orig_seq_no = Some(resend.seq_no);

    //                 // Check that our internal state of organizing SSRC for senders is correct.
    //                 assert_eq!(pkt.meta.ssrc, resend.ssrc);
    //                 assert_eq!(source.repairs(), Some(resend.ssrc));

    //                 // If the resent PT doesn't exist, the state is not correct as per above.
    //                 let pt = pt_rtx(&self.params, resend.pt).expect("Resend PT");

    //                 return Some(NextPacket {
    //                     pt,
    //                     ssrc: ssrc_rtx,
    //                     seq_no,
    //                     body: NextPacketBody::Resend { pkt, orig_seq_no },
    //                 });
    //             }
    //         };
    //     }
    // }

    pub(crate) fn sender_report_at(&self) -> Instant {
        let is_audio = self.rtx.is_none(); // this is maybe not correct, but it's all we got.
        self.last_sender_report + rr_interval(is_audio)
    }

    pub(crate) fn poll_keyframe_request(&mut self) -> Option<KeyframeRequestKind> {
        self.pending_request_keyframe.take()
    }

    pub(crate) fn handle_rtcp(&mut self, now: Instant, fb: RtcpFb) {
        use RtcpFb::*;
        match fb {
            ReceptionReport(r) => self.stats.update_with_rr(now, r),
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
            Twcc(_) => unreachable!("TWCC should be handled on session level"),
            _ => {}
        }
    }

    pub fn handle_nack(
        &mut self,
        entries: impl Iterator<Item = NackEntry>,
        now: Instant,
    ) -> Option<()> {
        // Turning NackEntry into SeqNo we need to know a SeqNo "close by" to lengthen the 16 bit
        // sequence number into the 64 bit we have in SeqNo.
        let seq_no = self.rtx_cache.first_cached_seq_no()?;
        let iter = entries.flat_map(|n| n.into_iter(seq_no));

        // Schedule all resends. They will be handled on next poll_packet
        for seq_no in iter {
            let resend = Resend {
                seq_no,
                queued_at: now,
            };
            self.resends.push_back(resend);
        }

        Some(())
    }

    pub(crate) fn maybe_create_sr(
        &mut self,
        now: Instant,
        // cname: &str,
        feedback: &mut VecDeque<Rtcp>,
    ) -> Option<()> {
        if now < self.sender_report_at() {
            return None;
        }

        let sr = self.create_sender_report(now);
        // let ds = self.create_sdes(cname);

        debug!("Created feedback SR: {:?}", sr);
        feedback.push_back(Rtcp::SenderReport(sr));
        // feedback.push_back(Rtcp::SourceDescription(ds));

        // Update timestamp to move time when next is created.
        self.last_sender_report = now;

        Some(())
    }

    fn create_sender_report(&self, now: Instant) -> SenderReport {
        SenderReport {
            sender_info: self.sender_info(now),
            reports: ReportList::new(),
        }
    }

    // fn create_sdes(&self, cname: &str) -> Descriptions {
    //     let mut s = Sdes {
    //         ssrc: self.ssrc,
    //         values: ReportList::new(),
    //     };
    //     s.values.push((SdesType::CNAME, cname.to_string()));

    //     let mut d = Descriptions {
    //         reports: ReportList::new(),
    //     };
    //     d.reports.push(s);

    //     d
    // }

    fn sender_info(&self, now: Instant) -> SenderInfo {
        let rtp_time = self.current_rtp_time(now).map(|t| t.numer()).unwrap_or(0);

        SenderInfo {
            ssrc: self.ssrc,
            ntp_time: MediaTime::new_ntp_time(now),
            rtp_time: rtp_time as u32,
            sender_packet_count: self.stats.packets as u32,
            sender_octet_count: self.stats.bytes as u32,
        }
    }

    fn current_rtp_time(&self, now: Instant) -> Option<MediaTime> {
        // This is the RTP time and the wallclock from the last written media.
        // We use that as an offset to current time (now), to calculate the
        // current RTP time.
        let (t, w) = self.rtp_and_wallclock?;

        // We assume the media was written some time in the past.
        let offset = now - w;

        let base = t.denom();

        // This might be in the wrong base.
        let rtp_time = t + offset.into();

        Some(rtp_time.rebase(base))
    }

    pub(crate) fn next_seq_no(&mut self) -> SeqNo {
        self.seq_no.inc()
    }

    pub(crate) fn last_packet(&self) -> Option<&[u8]> {
        if self.send_queue.is_empty() {
            self.rtx_cache.last_packet()
        } else {
            self.send_queue.back().map(|q| q.payload.as_ref())
        }
    }

    pub(crate) fn visit_stats(&mut self, snapshot: &mut StatsSnapshot, now: Instant) {
        self.stats.fill(snapshot, self.mid, self.rid, now);
    }
}

impl StreamTxStats {
    fn update_packet_counts(&mut self, bytes: u64, is_resend: bool) {
        self.packets += 1;
        self.bytes += bytes;
        if is_resend {
            self.bytes_resent += bytes;
            self.packets_resent += 1;
        }
    }

    fn increase_nacks(&mut self) {
        self.nacks += 1;
    }

    fn increase_plis(&mut self) {
        self.plis += 1;
    }

    fn increase_firs(&mut self) {
        self.firs += 1;
    }

    fn update_with_rr(&mut self, now: Instant, r: ReceptionReport) {
        let ntp_time = now.to_ntp_duration();
        let rtt = calculate_rtt_ms(ntp_time, r.last_sr_delay, r.last_sr_time);
        self.rtt = rtt;

        let ext_seq = {
            let prev = self.losses.last().map(|s| s.0).unwrap_or(r.max_seq as u64);
            let next = (r.max_seq & 0xffff) as u16;
            extend_u16(Some(prev), next)
        };

        self.losses
            .push((ext_seq, r.fraction_lost as f32 / u8::MAX as f32));
    }

    pub(crate) fn fill(
        &mut self,
        snapshot: &mut StatsSnapshot,
        mid: Mid,
        rid: Option<Rid>,
        now: Instant,
    ) {
        if self.bytes == 0 {
            return;
        }

        let key = (mid, rid);

        let loss = {
            let mut value = 0_f32;
            let mut total_weight = 0_u64;

            // just in case we received RRs out of order
            self.losses.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

            // average known RR losses weighted by their number of packets
            for it in self.losses.windows(2) {
                let [prev, next] = it else { continue };
                let weight = next.0.saturating_sub(prev.0);
                value += next.1 * weight as f32;
                total_weight += weight;
            }

            let result = value / total_weight as f32;
            result.is_finite().then_some(result)
        };

        self.losses.drain(..self.losses.len().saturating_sub(1));

        snapshot.egress.insert(
            key,
            MediaEgressStats {
                mid,
                rid,
                bytes: self.bytes + self.bytes_resent,
                packets: self.packets + self.packets_resent,
                firs: self.firs,
                plis: self.plis,
                nacks: self.nacks,
                rtt: self.rtt,
                loss,
                timestamp: now,
            },
        );
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
}
