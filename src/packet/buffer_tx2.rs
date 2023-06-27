use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp::{ExtensionValues, MediaTime, Rid, RtpHeader, SeqNo, Ssrc};

use super::{CodecPacketizer, PacketError, Packetizer, QueueSnapshot};
use super::{MediaKind, QueuePriority};

pub struct Packetized {
    pub data: Vec<u8>,
    pub first: bool,
    pub marker: bool,
    pub meta: PacketizedMeta,
    pub queued_at: Instant,

    /// Set when packet is first sent. This is so we can resend.
    pub seq_no: Option<SeqNo>,
    /// Whether this packetized is counted towards the PacketQueueStats (if it wansn't emitted yet)
    pub emitted: bool,
}

impl fmt::Debug for Packetized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packetized")
            .field("rtp_time", &self.meta.rtp_time)
            .field("len", &self.data.len())
            .field("first", &self.first)
            .field("last", &self.marker)
            .field("ssrc", &self.meta.ssrc)
            .field("seq_no", &self.seq_no)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PacketizedMeta {
    pub pt: Pt,
    pub rtp_time: MediaTime,
    pub ssrc: Ssrc,
    pub rid: Option<Rid>,
    pub ext_vals: ExtensionValues,
}

#[derive(Debug)]
pub struct PacketizingBuffer {
    pack: CodecPacketizer,
    queue: VecDeque<Packetized>,

    first_unemitted_index: usize,
    last_emitted_at: Option<Instant>,
    max_retain: usize,

    total: PacketQueueStats,
}

impl PacketizingBuffer {
    pub(crate) fn new(pack: CodecPacketizer, max_retain: usize) -> Self {
        PacketizingBuffer {
            pack,
            queue: VecDeque::new(),

            first_unemitted_index: 0,
            last_emitted_at: None,
            max_retain,

            total: PacketQueueStats::default(),
        }
    }

    pub fn push_sample(
        &mut self,
        now: Instant,
        data: &[u8],
        meta: PacketizedMeta,
        mtu: usize,
    ) -> Result<(), PacketError> {
        let packets = self.pack.packetize(mtu, data)?;
        let len = packets.len();

        assert!(len <= self.max_retain, "Must retain at least as many packets are needed for one sample");

        for (idx, packet) in packets.into_iter().enumerate() {
            let is_first = idx == 0;
            let is_last = idx == len - 1;
            let previous_data = self.queue.back().map(|p| p.packet.as_slice());
            let is_marker = self.pack.is_marker(packet.as_slice(), previous_data, is_last);
            self.queue_cache.push_packet(packet, now);
        }
        Ok(())
    }
}

use std::collections::BTreeMap;

type Packet = Vec<u8>,

struct PacketQueueCache {
    queue: PacketQueue,
    cache: PacketCache,
    last_popped_at: Option<Instant>,
}

impl PacketQueueCache {
    pub fn push_packet(&mut self, packet: Packet, now: Instant) {
        self.queue.push_packet(packet, now);
    }

    pub fn pop_packet(&mut self) -> Option<Packet> {
        let packet = self.queue.pop_packet()?;
        self.last_popped_at = Some(now);
        Some(packet)
    }

    pub fn cache_packet(&mut self, seq_no: SeqNo, packet: Packet, now: Instant) {
        self.cache.add_packet(seq_no, packet)
        Some((seq_no, packet))
    }

    pub fn last_popped_at(&self) -> Option<Instant> {
        self.last_popped_at
    }

    pub fn get_cached_packet(&self, seq_no: SeqNo) -> Option<&Packet> {
        self.cache.get_packet(seq_no)
    }

    pub fn find_cached_packet_smaller_than(&self, max_size: usize) -> Option<&Packet> {
        self.cache.get_packet_smaller_than(max_size)
    }

    pub fn first_cached_seq_no(&self) -> Option<SeqNo> {
        self.cache.first_seq_no()
    }

    pub fn snapshot(&mut self, now: Instant) -> QueueSnapshot {
        let first_queued_at = self.queue.peek_queued_at();
        let last_popped_at = self.last_popped_at;
        let queue_stats = self.queue.update_stats(now);

        QueueSnapshot {
            created_at: now,
            size: queue_stats.total_size,
            packet_count: queue_stats.packet_count,
            total_queue_time_origin: queue_stats.total_duration,
            last_emitted: last_popped_at,
            first_unsent: first_queued_at,
            priority: if queue_stats.packet_count > 0 {
                QueuePriority::Media
            } else {
                QueuePriority::Empty
            },
        }
    }
}

struct PacketQueue {
    queued_packets: VecDeque<QueuedPacket>,
    stats: PacketQueueStats,
}

struct QueuedPacket {
    seq_no: SeqNo,
    packet: Packet,
    queued_at: Instant,
}

impl PacketQueue {
    fn push_packet(&mut self, seq_no: SeqNo, packet: Packet, now: Instant) {
        self.queued_packets.push_back(QueuedPacket {
            seq_no,
            packet,
            queued_at: now,
        });
    }

    fn peek_seq_no(&self) -> Option<SeqNo> {
        let first = self.queued_packets.peek_front()?;
        Some(first.seq_no)
    }

    fn peek_queued_at(&self) -> Option<Instant> {
        let first = self.queued_packets.peek_front()?;
        Some(first.queued_at)
    }

    fn pop_packet(&mut self, now: Instant) -> Option<(SeqNo, Packet)> {
        let Some(QueuedPacket{seq_no, packet, queued_at}) = self.queued_packet.pop_front()?;
        self.stats.remove_packet(packet.len(), queued_at, now);
        Some((seq_no, packet))
    }

    fn update_stats(&mut self, now: Instant) -> &PacketQueueStats {
        self.stats.update(now);
        &self.stats
    }
}

#[derive(Debug, Default)]
struct PacketQueueStats {
    packet_count: usize,
    total_size: usize,
    total_duration: Duration,
    updated_at: Option<Instant>,
}

impl PacketQueueStats {
    fn update(&mut self, now: Instant) {
        if let Some(changed_at) = self.changed_at {
            let duration = now - changed_at;

            self.total_duration += duration * (self.packet_count as u32);
            self.updated_at = Some(now);
        }
    }

    fn add_packet(&mut self, packet_size: usize) {
        self.packet_count += 1;
        self.total_size += packet_size;
    }

    fn remove_packet(&mut self, packet_size: usize, packet_queued_at: Duration, now: Instant) {
        self.packet_count -= 1;
        self.total_size -= packet_size;
        self.total_duration -= (now - packet_queued_at);
        if self.packet_count == 0 {
            *self = Self::default();
        }
    }
}

#[derive(Debug)]
pub struct PacketCache {
    max_packet_count: usize,
    packet_by_seqnum: BTreeMap<SeqNo, Packet>,
}

impl PacketCache {
    fn new(max_packet_count: usize) -> Self {
        Self {
            max_packet_count,
            packet_by_seqnum: BTreeMap::new(),
        }
    }

    fn add_packet(&mut self, seqnum: u64, packet: Packet) {
        self.packet_by_seqnum.insert(seqnum, packet);
        self.remove_old_packets(now);
    }

    fn remove_old_packets(&mut self, now: Instant) {
        while self.packet_by_seqnum.len() > self.max_packet_count {
            self.packet_by_seqnum.pop_first();
        }
    }

    fn get_packet(&self, seq_no: SeqNo) -> Option<&Packet> {
        self.packet_by_seqnum.get(seq_no)
    }

    fn first_seq_no(&self) -> Option<SeqNo> {
        let first = self.packet_by_seqnum.first_entry()?;
        Some(first.key())
    }

    fn find_packet_smaller_than(&self, max_size: usize) -> Option<&Packet> {
        self
            .packet_by_seqnum
            .values()
            .rev()
            .filter(|packet| packet.data.len() < max_size)
            // TODO: Use .first()?
            .max_by_key(|packet| packet.data.len())
    }
}




// PETER: This would be better.
// impl<'a> NextPacket<'a> {
//     fn to_rtp_header(&self) -> RtpHeader {
//         RtpHeader {
//             payload_type: self.pt,
//             ssrc: self.ssrc,
//             sequence_number: *self.seq_no as u16,
//             timestamp: self.body.timestamp(),
//             ext_vals: self.body.ext_vals(),
//             marker: self.body.marker(),
//             ..Default::default()
//         };
//     }

//     /// Pass in the header to allow modifying it.
//     /// Returns the SRTP-padded payload size (the SRTP-padded packet size minus the header size).
//     fn to_rtp_packet(&self, header: &mut RtpHeader, exts: &ExtensionMap, packet_out: &mut[u8]) -> Option<usize> {
//         let header_len = header.write_to(packet_out, exts);
//         assert!(header_len % 4 == 0, "RTP header must be multiple of 4");
//         header.header_len = header_len;

//         let rtp_padded_payload_len = match self.body {
//             NextPacketBody::Regular { pkt } | NextPacketBody::Resend { pkt, .. } => {
//                 let payload = &pkt.data;

//                 let mut payload_out = &mut packet_out[header_len..];
        
//                 // For resends, the original seq_no is inserted before the payload.
//                 let mut original_seq_len = 0;
//                 if let Some(orig_seq_no) = orig_seq_no {
//                     original_seq_len = RtpHeader::write_original_sequence_number(payload_out, orig_seq_no);
//                     payload_out = &mut payload_out[original_seq_len..];
//                 }
        
//                 let payload_len = payload.len();
//                 payload_out[..payload_len].copy_from_slice(payload);
        
//                 let srtp_pad_len = RtpHeader::pad_packet(
//                     &mut packet_out[..],
//                     header_len,
//                     payload_len + original_seq_len,
//                     SRTP_BLOCK_SIZE,
//                 );
        
//                 let srtp_padded_payload_len = payload_len + original_seq_len + srtp_pad_len
//                 srtp_padded_payload_len
//             }
//             NextPacketBody::Blank { len: padding_len } => {
//                 let srtp_padded_payload_len = RtpHeader::create_padding_packet(
//                     &mut packet_out[..],
//                     padding_len,
//                     header_len,
//                     SRTP_BLOCK_SIZE,
//                 );
//                 if srtp_padded_payload_len == 0 {
//                     return None;
//                 }
//                 srtp_padded_packet_len
//             }
//         }
//         packet_out.truncate(header_len + srtp_padded_packet_len);
//         Some((header, srtp_padded_payload_len))
//     }
// }

    // PETER: This would be better.
    // fn serialize_rtp_packet(&self, header: RtpHeader, exts: &ExtensionMap, orig_seq_no: Option<u16>, payload: &[u8], packet_out: &mut[u8]) -> (usize, usize) {
    //     let header_len = header.write_to(packet_out, exts);

    //     let mut payload_out = &mut packet_out[header_len..];

    //     // For resends, the original seq_no is inserted before the payload.
    //     let mut original_seq_len = 0;
    //     if let Some(orig_seq_no) = orig_seq_no {
    //         original_seq_len = RtpHeader::write_original_sequence_number(payload_out, orig_seq_no);
    //         payload_out = &mut payload_out[original_seq_len..];
    //     }

    //     let payload_len = payload.len();
    //     payload_out[..payload_len].copy_from_slice(payload);

    //     let srtp_pad_len = RtpHeader::pad_packet(
    //         &mut packet_out[..],
    //         header_len,
    //         payload_len + original_seq_len,
    //         SRTP_BLOCK_SIZE,
    //     );

    //     let padded_payload_len = payload_len + original_seq_len + srtp_pad_len
    //     packet_out.truncate(header_len + padded_payload_len);

    //     (header_len, srtp_padded_payload_len)
    // }

    // fn serialize_padding_packet(&self, header: RtpHeader, exts: &ExtensionMap, padding_len: usize, packet_out: &mut[u8]) -> Option<(usize, usize)>{
    //     let header_len = header.write_to(packet_out, exts);
    //     let srtp_padded_payload_len = RtpHeader::create_padding_packet(
    //         &mut packet_out[..],
    //         padding_len,
    //         header_len,
    //         SRTP_BLOCK_SIZE,
    //     );
    //     if payload_len == 0 {
    //         return None;
    //     }

    //     Some((header_len, srtp_padded_payload_len))
    // }