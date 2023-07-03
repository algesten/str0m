use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use crate::rtp::ExtensionMap;
use crate::rtp::MediaTime;
use crate::rtp::NackEntry;
use crate::rtp::Pt;
use crate::rtp::SeqNo;
use crate::rtp::Ssrc;
use crate::session::PacketReceipt;
use crate::util::already_happened;
use crate::util::value_history::ValueHistory;

use super::rtx_cache::RtxCache;
use super::{rr_interval, StreamPacket};

/// Outgoing encoded stream.
#[derive(Debug)]
pub(crate) struct StreamTx {
    /// Unique identifier of the remote encoded stream.
    ssrc: Ssrc,

    /// Identifier of a resend (RTX) stream. If there is one.
    rtx: Option<Ssrc>,

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

    /// Keep last sequence number for extending the next.
    last_sent_seq_no: Option<SeqNo>,

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
    pub fn new(ssrc: Ssrc, rtx: Option<Ssrc>) -> Self {
        // https://www.rfc-editor.org/rfc/rfc3550#page-13
        // The initial value of the sequence number SHOULD be random (unpredictable)
        // to make known-plaintext attacks on encryption more difficult
        let next_seq_no_rtx = (rand::random::<u16>() as u64).into();

        debug!("Create StreamTx for SSRC: {}", ssrc);

        StreamTx {
            ssrc,
            rtx,
            seq_no_rtx: next_seq_no_rtx,
            last_used: already_happened(),
            rtp_and_wallclock: None,
            send_queue: VecDeque::new(),
            last_sent_seq_no: None,
            resends: VecDeque::new(),
            rtx_cache: RtxCache::new(1024, Duration::from_secs(3), false),
            last_sender_report: already_happened(),
            stats: StreamTxStats::default(),
        }
    }

    pub fn rtx(&self) -> Option<Ssrc> {
        self.rtx
    }

    pub fn enqueue(&mut self, packet: StreamPacket) {
        // Ensure RTX state is congruent.
        if self.rtx.is_some() {
            if packet.rtx_pt.is_none() {
                panic!("StreamTx has RTX, but packet is missing rtx_pt");
            }
        } else {
            if packet.rtx_pt.is_some() {
                panic!("StreamTx has no RTX, but packet is has rtx_pt");
            }
        }

        self.send_queue.push_back(packet);
    }

    pub fn handle_nack(
        &mut self,
        ssrc: Ssrc,
        entries: impl Iterator<Item = NackEntry>,
        now: Instant,
    ) -> Option<()> {
        // We do not handle resends unless we have the RTX mechanic set up.
        if self.rtx.is_none() {
            return None;
        }

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

        None
    }

    fn poll_packet_resend(&mut self, now: Instant, is_padding: bool) -> Option<NextPacket<'_>> {
        let pkt = loop {
            let resend = self.resends.pop_front()?;

            let pkt = self.rtx_cache.get_cached_packet_by_seq_no(resend.seq_no);

            // The seq_no could simply be too old to exist in the buffer, in which
            // case we will not do a resend.
            let Some(pkt) = pkt else {
                continue;
            };

            // Resends require the RTX mechanic, and we ignore packets without the rtx_pt.
            if pkt.rtx_pt.is_none() {
                continue;
            }

            if !pkt.nackable {
                trace!("SSRC {} resend {} not nackable", self.ssrc, pkt.seq_no);
            }

            break pkt;
        };

        if !is_padding {
            let len = pkt.data.len() as u64;
            self.stats.update_packet_counts(len, true);
            self.stats.bytes_retransmitted.push(now, len);
        }

        let seq_no = self.seq_no_rtx.inc();

        // The resend ssrc.
        let ssrc_rtx = self.rtx.unwrap_or(self.ssrc);
        // If we don't have a specific pt for RTX, we use the regular one.
        let pt = pkt.rtx_pt.unwrap_or(pkt.header.payload_type);

        let orig_seq_no = Some(pkt.seq_no);

        Some(NextPacket {
            pt,
            ssrc: ssrc_rtx,
            seq_no,
            body: NextPacketBody::Resend { pkt, orig_seq_no },
        })
    }

    fn poll_packet_regular(&mut self, now: Instant) -> Option<NextPacket<'_>> {
        // exit via ? here is ok since that means there is nothing to send.
        let pkt = self.send_queue.pop_front()?;

        let len = pkt.data.len() as u64;
        self.stats.update_packet_counts(len, false);
        self.stats.bytes_transmitted.push(now, len);

        let seq_no = pkt.header.sequence_number(self.last_sent_seq_no);
        self.last_sent_seq_no = Some(seq_no);

        let pt = pkt.header.payload_type;
        let ssrc = pkt.header.ssrc;

        self.rtx_cache.cache_sent_packet(pkt, now);
        let pkt = self.rtx_cache.get_cached_packet_by_seq_no(seq_no).unwrap(); // we just cached it

        Some(NextPacket {
            pt: pkt.header.payload_type,
            seq_no,
            ssrc: pkt.header.ssrc,
            body: NextPacketBody::Regular { pkt },
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

    pub(crate) fn stats(&self) -> &StreamTxStats {
        &self.stats
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
    pt: Pt,
    ssrc: Ssrc,
    seq_no: SeqNo,
    body: NextPacketBody<'a>,
}

enum NextPacketBody<'a> {
    /// A regular packetized packet
    Regular { pkt: &'a StreamPacket },
    /// A resend of a previously sent packet
    Resend {
        pkt: &'a StreamPacket,
        orig_seq_no: Option<SeqNo>,
    },
    /// An blank padding packet to be generated.
    Blank { len: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resend {
    ssrc: Ssrc,
    seq_no: SeqNo,
    queued_at: Instant,
}
