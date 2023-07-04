use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use crate::rtp::Ssrc;
use crate::rtp::{ExtensionMap, RtpHeader};
use crate::rtp::{ExtensionValues, MediaTime};
use crate::rtp::{Mid, NackEntry};
use crate::rtp::{Pt, Rid};
use crate::rtp::{SeqNo, SRTP_BLOCK_SIZE};
use crate::session::PacketReceipt;
use crate::util::already_happened;
use crate::util::value_history::ValueHistory;
use crate::RtcError;

use super::rtx_cache::RtxCache;
use super::{rr_interval, StreamPacket};

/// Outgoing encoded stream.
#[derive(Debug)]
pub struct StreamTx {
    /// Unique identifier of the remote encoded stream.
    ssrc: Ssrc,

    /// Payload type we are currently sending for.
    pt: Pt,

    /// Identifier of a resend (RTX) stream. If we are doing resends.
    rtx: Option<Ssrc>,

    /// Payload type for resends.
    rtx_pt: Option<Pt>,

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
    send_queue: VecDeque<StreamPacket>,

    /// Scheduled resends due to NACK or spurious padding.
    resends: VecDeque<Resend>,

    /// Cache of sent packets to be able to answer to NACKs as well as
    /// sending spurious resends as padding.
    rtx_cache: RtxCache,

    /// Last time we produced a SR.
    last_sender_report: Instant,

    /// Statistics of outgoing data.
    stats: StreamTxStats,
}

/// Holder of stats.
#[derive(Debug, Default)]
pub struct StreamTxStats {
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
    pub(crate) fn new(ssrc: Ssrc, pt: Pt, rtx: Option<Ssrc>, rtx_pt: Option<Pt>) -> Self {
        // https://www.rfc-editor.org/rfc/rfc3550#page-13
        // The initial value of the sequence number SHOULD be random (unpredictable)
        // to make known-plaintext attacks on encryption more difficult
        let next_seq_no_rtx = (rand::random::<u16>() as u64).into();

        debug!("Create StreamTx for SSRC: {}", ssrc);

        StreamTx {
            ssrc,
            pt,
            rtx,
            rtx_pt,
            seq_no_rtx: next_seq_no_rtx,
            last_used: already_happened(),
            rtp_and_wallclock: None,
            send_queue: VecDeque::new(),
            resends: VecDeque::new(),
            rtx_cache: RtxCache::new(1024, Duration::from_secs(3), false),
            last_sender_report: already_happened(),
            stats: StreamTxStats::default(),
        }
    }

    pub fn stats(&self) -> &StreamTxStats {
        &self.stats
    }

    /// Write RTP packet to a send stream.
    ///
    /// The `payload` argument is expected to be only the RTP payload, not the RTP packet header.
    ///
    /// * `payload` RTP packet payload, without header.
    /// * `seq_no` Sequence number to use for this packet.
    /// * `wallclock` Real world time that corresponds to the media time in the RTP packet. For an SFU,
    ///               this can be hard to know, since RTP packets typically only contain the media
    ///               time (RTP time). In the simplest SFU setup, the wallclock could simply be the
    ///               arrival time of the incoming RTP data. For better synchronization the SFU
    ///               probably needs to weigh in clock drifts and data provided via the statistics, receiver
    ///               reports etc.
    /// * `nackable` Whether we should respond this packet for incoming NACK from the remote peer. For
    ///              audio this is always false. For temporal encoded video, some packets are discardable
    ///              and this flag should be set accordingly.
    pub fn write_rtp(
        &mut self,
        seq_no: SeqNo,
        marker: bool,
        timestamp: MediaTime,
        wallclock: Instant,
        ext_vals: ExtensionValues,
        nackable: bool,
        payload: impl Into<Vec<u8>>,
    ) -> Result<(), RtcError> {
        //
        let header = RtpHeader {
            sequence_number: *seq_no as u16,
            marker,
            payload_type: self.pt,
            timestamp: timestamp.numer() as u32,
            ssrc: self.ssrc,
            ext_vals,
            ..Default::default()
        };

        let packet = StreamPacket {
            seq_no,
            header,
            payload: payload.into(),
            nackable,
            timestamp: already_happened(), // Updated on first ever poll_output.
        };

        self.send_queue.push_back(packet);

        Ok(())
    }

    pub(crate) fn handle_nack(
        &mut self,
        ssrc: Ssrc,
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
                ssrc,
                seq_no,
                queued_at: now,
            };
            self.resends.push_back(resend);
        }

        Some(())
    }

    pub(crate) fn poll_packet(
        &mut self,
        now: Instant,
        exts: &ExtensionMap,
        twcc: &mut u64,
        mid: Mid,
        rid: Rid,
        buf: &mut Vec<u8>,
    ) -> Option<PacketReceipt> {
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

        match next.kind {
            NextPacketKind::Regular => {
                header.ext_vals.rid = Some(rid);
                header.ext_vals.rid_repair = None;
            }
            NextPacketKind::Resend(_) | NextPacketKind::Blank(_) => {
                header.ext_vals.rid = None;
                header.ext_vals.rid_repair = Some(rid);
            }
        }

        buf.resize(2000, 0);
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

        Some(PacketReceipt {
            header: header.clone(),
            seq_no: next.seq_no,
            is_padding,
            payload_size: body_len,
        })
    }

    fn poll_packet_resend(&mut self, now: Instant, is_padding: bool) -> Option<NextPacket<'_>> {
        if self.rtx.is_none() || self.rtx_pt.is_none() {
            // We're not doing resends for non-RTX.
            return None;
        }

        let pkt = loop {
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

            break pkt;
        };

        if !is_padding {
            let len = pkt.payload.len() as u64;
            self.stats.update_packet_counts(len, true);
            self.stats.bytes_retransmitted.push(now, len);
        }

        let seq_no = self.seq_no_rtx.inc();

        let pt = self.rtx_pt.unwrap(); // checked above.
        let ssrc = self.rtx.unwrap(); // checked above.

        let orig_seq_no = pkt.seq_no;

        Some(NextPacket {
            kind: NextPacketKind::Resend(orig_seq_no),
            pt,
            ssrc,
            seq_no,
            pkt,
        })
    }

    fn poll_packet_regular(&mut self, now: Instant) -> Option<NextPacket<'_>> {
        // exit via ? here is ok since that means there is nothing to send.
        let pkt = self.send_queue.pop_front()?;

        let len = pkt.payload.len() as u64;
        self.stats.update_packet_counts(len, false);
        self.stats.bytes_transmitted.push(now, len);

        let seq_no = pkt.seq_no;

        self.rtx_cache.cache_sent_packet(pkt, now);
        let pkt = self.rtx_cache.get_cached_packet_by_seq_no(seq_no).unwrap(); // we just cached it

        Some(NextPacket {
            kind: NextPacketKind::Regular,
            pt: self.pt,
            seq_no,
            ssrc: self.ssrc,
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

    pub(crate) fn need_nack(&self) -> bool {
        !self.resends.is_empty()
    }

    pub(crate) fn set_rtx(&mut self, rtx: Option<Ssrc>, rtx_pt: Option<Pt>) {
        self.rtx = rtx;
        self.rtx_pt = rtx_pt;
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
}

struct NextPacket<'a> {
    kind: NextPacketKind,
    pt: Pt,
    ssrc: Ssrc,
    seq_no: SeqNo,
    pkt: &'a StreamPacket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextPacketKind {
    Regular,
    Resend(SeqNo),
    Blank(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resend {
    ssrc: Ssrc,
    seq_no: SeqNo,
    queued_at: Instant,
}
