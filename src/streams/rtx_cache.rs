use std::collections::BTreeMap;
use std::time::Duration;
use std::time::Instant;

use crate::io::DATAGRAM_MAX_PACKET_SIZE;
use crate::rtp_::SeqNo;

use super::RtpPacket;

const RTX_CACHE_SIZE_QUANTIZER: usize = 25;
const RTX_CACHE_QUANTIZE_SLOTS: usize = DATAGRAM_MAX_PACKET_SIZE / RTX_CACHE_SIZE_QUANTIZER;

#[derive(Debug)]
pub(crate) struct RtxCache {
    // Config
    max_packet_count: usize,
    max_packet_age: Duration,

    // Data, new additions here probably need to be cleared in [`clear`].
    packet_by_seq_no: BTreeMap<SeqNo, RtpPacket>,

    // Technically we want [Option<SeqNo>; X] to indicate the absence of
    // a SeqNo. However We can half the storage space by using the sentinel
    // values SeqNo::MAX to indicate None
    seq_no_by_quantized_size: [SeqNo; RTX_CACHE_QUANTIZE_SLOTS],
}

impl RtxCache {
    pub fn new(max_packet_count: usize, max_packet_age: Duration) -> Self {
        Self {
            max_packet_count,
            max_packet_age,
            packet_by_seq_no: BTreeMap::new(),
            seq_no_by_quantized_size: [SeqNo::MAX; RTX_CACHE_QUANTIZE_SLOTS],
        }
    }

    pub fn cache_sent_packet(&mut self, packet: RtpPacket, now: Instant) {
        let seq_no = packet.seq_no;
        let quantized_size = packet.payload.len() / RTX_CACHE_SIZE_QUANTIZER;
        self.packet_by_seq_no.insert(seq_no, packet);
        self.seq_no_by_quantized_size[quantized_size] = seq_no;
        self.remove_old_packets(now);
    }

    pub fn first_cached_seq_no(&self) -> Option<SeqNo> {
        self.packet_by_seq_no.keys().next().copied()
    }

    pub fn get_cached_packet_by_seq_no(&mut self, seq_no: SeqNo) -> Option<&mut RtpPacket> {
        self.packet_by_seq_no.get_mut(&seq_no)
    }

    pub fn get_cached_packet_smaller_than(&mut self, max_size: usize) -> Option<&mut RtpPacket> {
        let quantized_size = max_size / RTX_CACHE_SIZE_QUANTIZER;

        let seq_no = self.seq_no_by_quantized_size[..quantized_size]
            .iter()
            .rev()
            .filter(|seq_no| !seq_no.is_max())
            .find(|seq_no| self.packet_by_seq_no.contains_key(seq_no))?;

        self.get_cached_packet_by_seq_no(*seq_no)
    }

    fn remove_old_packets(&mut self, now: Instant) {
        // Confirmed in a microbenchmark that this is faster than removing one-by-one in a while-loop.
        if let Some(first_seq_no_thats_not_too_old) = self.find_first_seq_no_thats_not_too_old(now)
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
            return Some(None);
        };

        if first_packet.timestamp <= min_queued_at {
            return Some(
                self.packet_by_seq_no
                    .iter()
                    .find(|(_, packet)| packet.timestamp > min_queued_at)
                    .map(|(seq_no, _packet)| seq_no)
                    .cloned(),
            );
        }

        None
    }

    pub(crate) fn last_packet(&self) -> Option<&[u8]> {
        self.packet_by_seq_no
            .values()
            .next_back()
            .map(|e| e.payload.as_ref())
    }

    pub(crate) fn clear(&mut self) {
        self.packet_by_seq_no.clear();
        self.seq_no_by_quantized_size = [SeqNo::MAX; RTX_CACHE_QUANTIZE_SLOTS];
    }
}

#[cfg(test)]
mod test {
    use crate::rtp_::{MediaTime, RtpHeader};

    use super::*;

    #[test]
    fn rtx_cache() {
        let epoch = Instant::now();
        let after =
            |millis_since_epoch: u32| epoch + Duration::from_millis(millis_since_epoch as u64);
        let packet = |seq_no: SeqNo, millis_since_epoch: u32| RtpPacket {
            header: RtpHeader {
                marker: false,
                payload_type: 1.into(),
                ssrc: 1.into(),
                ..Default::default()
            },
            seq_no,
            time: MediaTime::new(0, 90_000),
            payload: millis_since_epoch.to_be_bytes().to_vec(),
            timestamp: after(millis_since_epoch),
            nackable: true,
        };

        let max_packet_count = 0;
        let max_duration = Duration::from_secs(3);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration);
        rtx_cache.cache_sent_packet(packet(1.into(), 10), after(10));
        assert_eq!(None, rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(1000));

        let max_packet_count = 1;
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration);
        rtx_cache.cache_sent_packet(packet(1.into(), 10), after(10));
        assert_eq!(Some(1.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&mut packet(1.into(), 10)),
            rtx_cache.get_cached_packet_by_seq_no(1.into())
        );
        assert_eq!(
            Some(&mut packet(1.into(), 10)),
            rtx_cache.get_cached_packet_smaller_than(1000)
        );
        assert_eq!(
            Some(&mut packet(1.into(), 10)),
            rtx_cache.get_cached_packet_smaller_than(25)
        );
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(24));
        rtx_cache.cache_sent_packet(packet(2.into(), 20), after(20));
        assert_eq!(Some(2.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(
            Some(&mut packet(2.into(), 20)),
            rtx_cache.get_cached_packet_by_seq_no(2.into())
        );
        assert_eq!(
            Some(&mut packet(2.into(), 20)),
            rtx_cache.get_cached_packet_smaller_than(1000)
        );
        assert_eq!(
            Some(&mut packet(2.into(), 20)),
            rtx_cache.get_cached_packet_smaller_than(25)
        );
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(24));

        let max_packet_count = 100;
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration);
        for i in 1..=200u32 {
            let seq_no = (201 - i as u64).into();
            let pkt = packet(seq_no, (201 - i) * 10);
            let now = after(i * 10);
            rtx_cache.cache_sent_packet(pkt, now);
        }
        assert_eq!(Some(101.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&mut packet(200.into(), 2000)),
            rtx_cache.get_cached_packet_by_seq_no(200.into())
        );
        assert_eq!(
            Some(&mut packet(101.into(), 1010)),
            rtx_cache.get_cached_packet_by_seq_no(101.into())
        );
        // TODO: Make it possible to get packets by max_size even when they are sent out of order.
        // assert_eq!(Some((200.into(), &mut packet(2000))), rtx_cache.get_cached_packet_smaller_than(1000));

        let max_duration = Duration::from_secs(0);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration);
        rtx_cache.cache_sent_packet(packet(1.into(), 10), after(10));
        assert_eq!(None, rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(1000));

        let max_packet_count = 200;
        let max_duration = Duration::from_secs(1);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration);
        for i in 1..=200u32 {
            let seq_no = (201 - i as u64).into();
            let pkt = packet(seq_no, (201 - i) * 10);
            let now = after(i * 10);
            rtx_cache.cache_sent_packet(pkt, now);
        }
        assert_eq!(Some(101.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&mut packet(200.into(), 2000)),
            rtx_cache.get_cached_packet_by_seq_no(200.into())
        );
        assert_eq!(
            Some(&mut packet(101.into(), 1010)),
            rtx_cache.get_cached_packet_by_seq_no(101.into())
        );

        let max_packet_count = 0;
        let max_duration = Duration::from_secs(3);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration);
        rtx_cache.cache_sent_packet(packet(1.into(), 10), after(10));
        assert_eq!(None, rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(1000));

        let max_packet_count = 1;
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration);
        rtx_cache.cache_sent_packet(packet(1.into(), 10), after(10));
        assert_eq!(Some(1.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&mut packet(1.into(), 10)),
            rtx_cache.get_cached_packet_by_seq_no(1.into())
        );
        assert_eq!(
            Some(&mut packet(1.into(), 10)),
            rtx_cache.get_cached_packet_smaller_than(1000)
        );
        assert_eq!(
            Some(&mut packet(1.into(), 10)),
            rtx_cache.get_cached_packet_smaller_than(25)
        );
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(24));
        rtx_cache.cache_sent_packet(packet(2.into(), 20), after(20));
        assert_eq!(Some(2.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(
            Some(&mut packet(2.into(), 20)),
            rtx_cache.get_cached_packet_by_seq_no(2.into())
        );
        assert_eq!(
            Some(&mut packet(2.into(), 20)),
            rtx_cache.get_cached_packet_smaller_than(1000)
        );
        assert_eq!(
            Some(&mut packet(2.into(), 20)),
            rtx_cache.get_cached_packet_smaller_than(25)
        );
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(24));

        let max_packet_count = 100;
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration);
        for i in 1..=200u32 {
            let seq_no = (201 - i as u64).into();
            let pkt = packet(seq_no, (201 - i) * 10);
            let now = after(i * 10);
            rtx_cache.cache_sent_packet(pkt, now);
        }
        assert_eq!(Some(101.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&mut packet(200.into(), 2000)),
            rtx_cache.get_cached_packet_by_seq_no(200.into())
        );
        assert_eq!(
            Some(&mut packet(101.into(), 1010)),
            rtx_cache.get_cached_packet_by_seq_no(101.into())
        );
        // TODO: Make it possible to get packets by max_size even when they are sent out of order.
        // assert_eq!(Some((200.into(), &mut packet(2000))), rtx_cache.get_cached_packet_smaller_than(1000));

        let max_duration = Duration::from_secs(0);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration);
        rtx_cache.cache_sent_packet(packet(1.into(), 10), after(10));
        assert_eq!(None, rtx_cache.first_cached_seq_no());
        assert_eq!(None, rtx_cache.get_cached_packet_by_seq_no(1.into()));
        assert_eq!(None, rtx_cache.get_cached_packet_smaller_than(1000));

        let max_packet_count = 200;
        let max_duration = Duration::from_secs(1);
        let mut rtx_cache = RtxCache::new(max_packet_count, max_duration);
        for i in 1..=200u32 {
            let seq_no = (201 - i as u64).into();
            let pkt = packet(seq_no, (201 - i) * 10);
            let now = after(i * 10);
            rtx_cache.cache_sent_packet(pkt, now);
        }
        assert_eq!(Some(101.into()), rtx_cache.first_cached_seq_no());
        assert_eq!(
            Some(&mut packet(200.into(), 2000)),
            rtx_cache.get_cached_packet_by_seq_no(200.into())
        );
        assert_eq!(
            Some(&mut packet(101.into(), 1010)),
            rtx_cache.get_cached_packet_by_seq_no(101.into())
        );
    }
}
