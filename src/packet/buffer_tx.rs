use std::collections::HashMap;
use std::collections::{BTreeMap, VecDeque};

use std::fmt;
use std::time::{Duration, Instant};

use crate::media::RtpPacketToSend;
use crate::rtp::{ExtensionValues, MediaTime, Rid, RtpHeader, SeqNo, Ssrc};

use super::ring::Ident;
use super::ring::RingBuf;
use super::{CodecPacketizer, PacketError, Packetizer, QueueSnapshot};
use super::{MediaKind, QueuePriority};

#[derive(PartialEq, Eq)]
pub struct Packetized {
    pub data: Vec<u8>,
    pub first: bool,
    pub marker: bool,
    pub meta: PacketizedMeta,
    pub queued_at: Instant,

    /// If we are in rtp_mode, this is what to send.
    // TODO: Consider using an enum of Packetized|RtpPacketToSend, or unifying in some other way.
    pub rtp_mode_packet: Option<RtpPacketToSend>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketizedMeta {
    pub rtp_time: MediaTime,
    pub ssrc: Ssrc,
    pub rid: Option<Rid>,
    pub ext_vals: ExtensionValues,
}

#[derive(Debug)]
pub struct PacketizingBuffer {
    pack: CodecPacketizer,
    queue: RingBuf<Packetized>,
    rtx_cache: RtxCache,

    emit_next: Ident,
    last_emit: Option<Instant>,
    max_retain: usize,

    total: TotalQueue,

    // Set when we first discover the SSRC
    ssrc: Option<Ssrc>,
}

const SIZE_BUCKET: usize = 25;

impl PacketizingBuffer {
    pub(crate) fn new(
        pack: CodecPacketizer,
        max_retain: usize,
        max_rtx_packet_count: usize,
        max_rtx_duration: Duration,
    ) -> Self {
        // TODO: Make configurable
        let rtx_evict_in_batches = false;
        PacketizingBuffer {
            pack,
            queue: RingBuf::new(max_retain),
            rtx_cache: RtxCache::new(max_rtx_packet_count, max_rtx_duration, rtx_evict_in_batches),

            emit_next: Ident::default(),
            last_emit: None,
            max_retain,

            total: TotalQueue::default(),
            ssrc: None,
        }
    }

    pub fn push_sample(
        &mut self,
        now: Instant,
        data: &[u8],
        meta: PacketizedMeta,
        mtu: usize,
    ) -> Result<bool, PacketError> {
        let chunks = self.pack.packetize(mtu, data)?;
        let len = chunks.len();
        self.total.move_time_forward(now);

        assert!(
            len <= self.max_retain,
            "Data larger than send buffer {} > {}",
            data.len(),
            self.max_retain
        );

        let mut chunk_start_ident = None;
        let mut data_len = 0;

        if self.ssrc.is_none() {
            self.ssrc = Some(meta.ssrc);
        }

        for (idx, data) in chunks.into_iter().enumerate() {
            let first = idx == 0;
            let last = idx == len - 1;

            let previous_data = self.queue.last().map(|p| p.data.as_slice());
            let marker = self.pack.is_marker(data.as_slice(), previous_data, last);

            self.total.increase(now, Duration::ZERO, data.len());
            data_len += data.len();

            let rtp = Packetized {
                first,
                marker,
                data,
                meta,
                queued_at: now,

                rtp_mode_packet: None,
            };

            let (ident, evicted) = self.queue.push(rtp);

            if chunk_start_ident.is_none() {
                chunk_start_ident = Some(ident);
            }

            if let Some(evicted) = evicted {
                self.handle_evicted(now, evicted);
            }
        }

        let first = self.queue.first_ident();
        let overflow = Some(self.emit_next) < first;

        if overflow {
            self.overflow_reset(now, len, data_len, chunk_start_ident.unwrap());
        }

        Ok(overflow)
    }

    pub fn push_rtp_packet(&mut self, mut rtp_packet: RtpPacketToSend, now: Instant) -> bool {
        self.total.move_time_forward(now);
        self.total
            .increase(now, Duration::ZERO, rtp_packet.payload.len());

        if self.ssrc.is_none() {
            self.ssrc = Some(rtp_packet.ssrc);
        }

        let data_len = rtp_packet.payload.len();

        let rtp = Packetized {
            first: true,
            marker: rtp_packet.marker,
            data: std::mem::take(&mut rtp_packet.payload),
            meta: PacketizedMeta {
                // Only the numerator is used here when the packet is sent, so use any clock rate.
                rtp_time: MediaTime::new(rtp_packet.timestamp as i64, 90000),
                ssrc: rtp_packet.ssrc,
                rid: rtp_packet.header_extensions.rid,
                ext_vals: rtp_packet.header_extensions,
            },
            queued_at: now,

            rtp_mode_packet: Some(rtp_packet),
        };

        let (ident, evicted) = self.queue.push(rtp);

        if let Some(evicted) = evicted {
            self.handle_evicted(now, evicted);
        }

        let overflow = Some(self.emit_next) < self.queue.first_ident();

        if overflow {
            self.overflow_reset(now, 1, data_len, ident);
        }

        overflow
    }

    fn overflow_reset(
        &mut self,
        now: Instant,
        unsent_count: usize,
        unsent_size: usize,
        start_at: Ident,
    ) {
        // The new write resets the total.
        self.total = TotalQueue {
            unsent_count,
            unsent_size,
            last: Some(now),
            queue_time: Duration::ZERO,
        };

        // Remove all entries up until the new emit_next
        while self.emit_next < start_at {
            self.queue.remove(self.emit_next);
            self.emit_next = self.emit_next.increase();
        }

        self.emit_next = start_at;

        warn!("Send buffer overflow, increase send buffer size");
    }

    fn handle_evicted(&mut self, now: Instant, p: Packetized) {
        let queue_time = now - p.queued_at;
        self.total.decrease(p.data.len(), queue_time);
    }

    pub fn take_next(&mut self, now: Instant) -> Option<Packetized> {
        self.total.move_time_forward(now);

        let mut next = self.queue.remove(self.emit_next)?;

        let queue_time = now - next.queued_at;
        self.total.decrease(next.data.len(), queue_time);

        self.emit_next = self.emit_next.increase();
        self.last_emit = Some(now);

        Some(next)
    }

    pub fn cache_sent(&mut self, seq_no: SeqNo, pkt: Packetized, now: Instant) {
        self.rtx_cache.cache_sent_packet(seq_no, pkt, now);
    }

    pub fn get(&self, seq_no: SeqNo) -> Option<&Packetized> {
        self.rtx_cache.get_cached_packet_by_seq_no(seq_no)
    }

    pub fn first_seq_no_in_rtx_cache(&self) -> Option<SeqNo> {
        self.rtx_cache.first_cached_seq_no()
    }

    pub fn queue_snapshot(&mut self, now: Instant) -> QueueSnapshot {
        self.total.move_time_forward(now);

        QueueSnapshot {
            created_at: now,
            size: self.total.unsent_size,
            packet_count: self.total.unsent_count as u32,
            total_queue_time_origin: self.total.queue_time,
            last_emitted: self.last_emit,
            first_unsent: self.queue.get(self.emit_next).map(|p| p.queued_at),
            priority: if self.total.unsent_count > 0 {
                QueuePriority::Media
            } else {
                QueuePriority::Empty
            },
        }
    }

    /// The size of the resend history in this buffer.
    pub fn history_size(&self) -> usize {
        self.queue.len()
    }

    /// Find a historic packet that is smaller than the given max_size.
    pub fn historic_packet_smaller_than(&self, max_size: usize) -> Option<(SeqNo, &Packetized)> {
        self.rtx_cache.get_cached_packet_smaller_than(max_size)
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc.expect("Send buffer to have an SSRC")
    }
}

// Total queue time in buffer. This lovely drawing explains how to add more time.
//
// -time--------------------------------------------------------->
//
// +--------------+
// |              |
// +--------------+
//      +---------+                          Already
//      |         |                           queued
//      +---------+                         durations
//          +-----+
//          |     |
//          +-----+
//                       +-+
//                       | |         <-----  Add next
//                       +-+                  packet
//
//
//
// +--------------+--------+
// |              |@@@@@@@@|
// +--------------+--------+
//      +---------+--------+                 The @ is
//      |         |@@@@@@@@|                  what's
//      +---------+--------+                  added
//          +-----+--------+
//          |     |@@@@@@@@|
//          +-----+--------+
//                       +-+
//                       |@|
//                       +-+
#[derive(Debug, Default)]
struct TotalQueue {
    /// Number of unsent packets.
    unsent_count: usize,
    /// The data size (bytes) of the unsent packets.
    unsent_size: usize,
    /// When we last added some value to `queue_time`.
    last: Option<Instant>,
    /// The total queue time of all the unsent packets.
    queue_time: Duration,
}

impl TotalQueue {
    fn move_time_forward(&mut self, now: Instant) {
        if let Some(last) = self.last {
            assert!(self.unsent_count > 0);
            let from_last = now - last;
            self.queue_time += from_last * (self.unsent_count as u32);
            self.last = Some(now);
        } else {
            assert!(self.unsent_count == 0);
            assert!(self.unsent_size == 0);
            assert!(self.queue_time == Duration::ZERO);
        }
    }

    fn increase(&mut self, now: Instant, queue_time: Duration, size: usize) {
        self.unsent_count += 1;
        self.unsent_size += size;
        self.queue_time += queue_time;
        self.last = Some(now);
    }

    fn decrease(&mut self, size: usize, queue_time: Duration) {
        self.unsent_count -= 1;
        self.unsent_size -= size;
        self.queue_time -= queue_time;
        if self.unsent_count == 0 {
            assert!(self.unsent_size == 0);
            self.queue_time = Duration::ZERO;
            self.last = None;
        }
    }
}

impl fmt::Debug for Packetized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packetized")
            .field("rtp_time", &self.meta.rtp_time)
            .field("len", &self.data.len())
            .field("first", &self.first)
            .field("last", &self.marker)
            .field("ssrc", &self.meta.ssrc)
            .finish()
    }
}

#[derive(Debug)]
pub struct RtxCache {
    max_packet_count: usize,
    max_packet_age: Duration,
    evict_in_batches: bool,
    packet_by_seq_no: BTreeMap<SeqNo, Packetized>,
    seq_no_by_quantized_size: BTreeMap<usize, SeqNo>,
    last_sent_time: Option<Instant>,
}

const RTX_CACHE_SIZE_QUANTIZER: usize = 25;

impl RtxCache {
    fn new(max_packet_count: usize, max_packet_age: Duration, evict_in_batches: bool) -> Self {
        Self {
            max_packet_count,
            max_packet_age,
            evict_in_batches,
            packet_by_seq_no: BTreeMap::new(),
            seq_no_by_quantized_size: BTreeMap::new(),
            last_sent_time: None,
        }
    }

    fn cache_sent_packet(&mut self, seq_no: SeqNo, packet: Packetized, now: Instant) {
        let quantized_size = packet.data.len() / RTX_CACHE_SIZE_QUANTIZER;
        self.packet_by_seq_no.insert(seq_no, packet);
        self.seq_no_by_quantized_size.insert(quantized_size, seq_no);
        self.last_sent_time = Some(now);
        self.remove_old_packets(now);
    }

    fn first_cached_seq_no(&self) -> Option<SeqNo> {
        self.packet_by_seq_no.keys().next().copied()
    }

    fn last_sent_time(&self) -> Option<Instant> {
        self.last_sent_time
    }

    fn get_cached_packet_by_seq_no(&self, seq_no: SeqNo) -> Option<&Packetized> {
        self.packet_by_seq_no.get(&seq_no)
    }

    fn get_cached_packet_smaller_than(&self, max_size: usize) -> Option<(SeqNo, &Packetized)> {
        let quantized_size = max_size / RTX_CACHE_SIZE_QUANTIZER;
        let seq_no = *self
            .seq_no_by_quantized_size
            .range(..quantized_size)
            .next_back()?
            .1;
        Some((seq_no, self.get_cached_packet_by_seq_no(seq_no)?))
    }

    fn remove_old_packets(&mut self, now: Instant) {
        if self.evict_in_batches {
            if let Some(first_seq_no_thats_not_too_old) =
                self.find_first_seq_no_thats_not_too_old(now)
            {
                if let Some(first_seq_no_thats_not_too_old) = first_seq_no_thats_not_too_old {
                    self.packet_by_seq_no = self
                        .packet_by_seq_no
                        .split_off(&first_seq_no_thats_not_too_old);
                } else {
                    // They are all too old
                    self.packet_by_seq_no.clear();
                }
            }
        } else {
            while let Some(first_seq_no_thats_too_old) = self.find_first_seq_no_thats_too_old(now) {
                self.packet_by_seq_no.remove(&first_seq_no_thats_too_old);
            }
        }
    }

    fn find_first_seq_no_thats_too_old(&self, now: Instant) -> Option<SeqNo> {
        if self.packet_by_seq_no.len() > self.max_packet_count {
            let first_seq_no = self.packet_by_seq_no.keys().next()?;
            // Too old because of max_packet_count.
            return Some(*first_seq_no);
        }
        // If the max_packet_age is so old that checked_sub returns None, we shouldn't remove based on max_packet_age.
        let min_queued_at = now.checked_sub(self.max_packet_age)?;

        let (first_seq_no, first_packet) = self.packet_by_seq_no.iter().next()?;
        if first_packet.queued_at <= min_queued_at {
            // Too old because of max_packet_age
            return Some(*first_seq_no);
        }
        None
    }

    // None == nothing is too old
    // Some(None) == everything is too old
    // Some(Some(seq_no)) == everything before this is too old
    fn find_first_seq_no_thats_not_too_old(&self, now: Instant) -> Option<Option<SeqNo>> {
        let too_many_packets_count = self
            .packet_by_seq_no
            .len()
            .saturating_sub(self.max_packet_count);
        if too_many_packets_count > 0 {
            return Some(
                self.packet_by_seq_no
                    .keys()
                    .nth(too_many_packets_count)
                    .cloned(),
            );
        }

        // If the max_packet_age is so old that checked_sub returns None, we shouldn't remove based on max_packet_age.
        let min_queued_at = now.checked_sub(self.max_packet_age)?;

        // There is no packet, so I guess we'll clear it.  But that's a no-op anyway.
        let Some(first_packet) = self.packet_by_seq_no.values().next() else {
            return Some(None)
        };

        if first_packet.queued_at <= min_queued_at {
            return Some(
                self.packet_by_seq_no
                    .iter()
                    .find(|(_, packet)| packet.queued_at > min_queued_at)
                    .map(|(seq_no, _packet)| seq_no)
                    .cloned(),
            );
        }

        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn total_queue() {
        let mut total_queue = TotalQueue::default();
        let now = Instant::now();
        total_queue.increase(now, Duration::ZERO, 0);
        total_queue.increase(now, Duration::ZERO, 1);
        total_queue.decrease(1, Duration::ZERO);
        // Doesn't panic
        total_queue.move_time_forward(now + Duration::from_millis(1));
    }

    #[test]
    fn rtx_cache() {
        let epoch = Instant::now();
        let after =
            |millis_since_epoch: u32| epoch + Duration::from_millis(millis_since_epoch as u64);
        let packet = |millis_since_epoch: u32| Packetized {
            first: true,
            marker: false,
            meta: PacketizedMeta {
                rtp_time: MediaTime::new(millis_since_epoch as i64, 1000),
                ssrc: 1.into(),
                rid: None,
                ext_vals: ExtensionValues::default(),
            },
            data: millis_since_epoch.to_be_bytes().to_vec(),
            queued_at: after(millis_since_epoch),
            rtp_mode_packet: None,
        };

        let evict_in_batches = false;
        let max_packet_count = 0;
        let max_duration = Duration::from_secs(3);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        rtx_cache.cache_sent_packet(1.into(), packet(10), after(10));
        assert_eq!(None, rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(1000));

        let max_packet_count = 1;
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        rtx_cache.cache_sent_packet(1.into(), packet(10), after(10));
        assert_eq!(Some(1.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&packet(10)),
            rtx_cache.get_cached_packet_by_seq_no(1.into())
        );
        assert_eq!(
            Some((1.into(), &packet(10))),
            rtx_cache.get_cached_packet_smaller_than(1000)
        );
        assert_eq!(
            Some((1.into(), &packet(10))),
            rtx_cache.get_cached_packet_smaller_than(25)
        );
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(24));
        rtx_cache.cache_sent_packet(2.into(), packet(20), after(20));
        assert_eq!(Some(2.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(
            Some(&packet(20)),
            rtx_cache.get_cached_packet_by_seq_no(2.into())
        );
        assert_eq!(
            Some((2.into(), &packet(20))),
            rtx_cache.get_cached_packet_smaller_than(1000)
        );
        assert_eq!(
            Some((2.into(), &packet(20))),
            rtx_cache.get_cached_packet_smaller_than(25)
        );
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(24));

        let max_packet_count = 100;
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        for i in 1..=200u32 {
            let seq_no = (201 - i as u64).into();
            let pkt = packet((201 - i) * 10);
            let now = after(i * 10);
            rtx_cache.cache_sent_packet(seq_no, pkt, now);
        }
        assert_eq!(Some(101.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&packet(2000)),
            rtx_cache.get_cached_packet_by_seq_no(200.into())
        );
        assert_eq!(
            Some(&packet(1010)),
            rtx_cache.get_cached_packet_by_seq_no(101.into())
        );
        // TODO: Make it possible to get packets by max_size even when they are sent out of order.
        // assert_eq!(Some((200.into(), &packet(2000))), rtx_cache.get_cached_packet_smaller_than(1000));

        let max_duration = Duration::from_secs(0);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        rtx_cache.cache_sent_packet(1.into(), packet(10), after(10));
        assert_eq!(None, rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(1000));

        let max_packet_count = 200;
        let max_duration = Duration::from_secs(1);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        for i in 1..=200u32 {
            let seq_no = (201 - i as u64).into();
            let pkt = packet((201 - i) * 10);
            let now = after(i * 10);
            rtx_cache.cache_sent_packet(seq_no, pkt, now);
        }
        assert_eq!(Some(101.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&packet(2000)),
            rtx_cache.get_cached_packet_by_seq_no(200.into())
        );
        assert_eq!(
            Some(&packet(1010)),
            rtx_cache.get_cached_packet_by_seq_no(101.into())
        );

        let evict_in_batches = true;
        let max_packet_count = 0;
        let max_duration = Duration::from_secs(3);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        rtx_cache.cache_sent_packet(1.into(), packet(10), after(10));
        assert_eq!(None, rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(1000));

        let max_packet_count = 1;
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        rtx_cache.cache_sent_packet(1.into(), packet(10), after(10));
        assert_eq!(Some(1.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&packet(10)),
            rtx_cache.get_cached_packet_by_seq_no(1.into())
        );
        assert_eq!(
            Some((1.into(), &packet(10))),
            rtx_cache.get_cached_packet_smaller_than(1000)
        );
        assert_eq!(
            Some((1.into(), &packet(10))),
            rtx_cache.get_cached_packet_smaller_than(25)
        );
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(24));
        rtx_cache.cache_sent_packet(2.into(), packet(20), after(20));
        assert_eq!(Some(2.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(
            Some(&packet(20)),
            rtx_cache.get_cached_packet_by_seq_no(2.into())
        );
        assert_eq!(
            Some((2.into(), &packet(20))),
            rtx_cache.get_cached_packet_smaller_than(1000)
        );
        assert_eq!(
            Some((2.into(), &packet(20))),
            rtx_cache.get_cached_packet_smaller_than(25)
        );
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(24));

        let max_packet_count = 100;
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        for i in 1..=200u32 {
            let seq_no = (201 - i as u64).into();
            let pkt = packet((201 - i) * 10);
            let now = after(i * 10);
            rtx_cache.cache_sent_packet(seq_no, pkt, now);
        }
        assert_eq!(Some(101.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&packet(2000)),
            rtx_cache.get_cached_packet_by_seq_no(200.into())
        );
        assert_eq!(
            Some(&packet(1010)),
            rtx_cache.get_cached_packet_by_seq_no(101.into())
        );
        // TODO: Make it possible to get packets by max_size even when they are sent out of order.
        // assert_eq!(Some((200.into(), &packet(2000))), rtx_cache.get_cached_packet_smaller_than(1000));

        let max_duration = Duration::from_secs(0);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        rtx_cache.cache_sent_packet(1.into(), packet(10), after(10));
        assert_eq!(None, rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(1000));

        let max_packet_count = 200;
        let max_duration = Duration::from_secs(1);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration, evict_in_batches);
        for i in 1..=200u32 {
            let seq_no = (201 - i as u64).into();
            let pkt = packet((201 - i) * 10);
            let now = after(i * 10);
            rtx_cache.cache_sent_packet(seq_no, pkt, now);
        }
        assert_eq!(Some(101.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&packet(2000)),
            rtx_cache.get_cached_packet_by_seq_no(200.into())
        );
        assert_eq!(
            Some(&packet(1010)),
            rtx_cache.get_cached_packet_by_seq_no(101.into())
        );
    }
}
