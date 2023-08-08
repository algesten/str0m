use std::time::{Duration, Instant};

use crate::rtp_::SeqNo;

use super::rtx_cache::RtxCache;
use super::RtpPacket;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PacketStore {
    Cached(RtxCache),
    Uncached(KeepLastPacket),
}

#[derive(Debug, Default)]
pub(crate) struct KeepLastPacket {
    last_packet: Option<RtpPacket>,
}

impl PacketStore {
    pub fn by_seq_no(&mut self, seq_no: SeqNo) -> Option<&mut RtpPacket> {
        match self {
            PacketStore::Cached(v) => v.get_cached_packet_by_seq_no(seq_no),
            PacketStore::Uncached(_) => None,
        }
    }

    pub fn push(&mut self, pkt: RtpPacket, now: Instant) {
        match self {
            PacketStore::Cached(v) => v.cache_sent_packet(pkt, now),
            PacketStore::Uncached(v) => v.last_packet = Some(pkt),
        }
    }

    pub fn last_packet(&mut self) -> Option<&mut RtpPacket> {
        match self {
            PacketStore::Cached(v) => v.last_packet(),
            PacketStore::Uncached(v) => v.last_packet.as_mut(),
        }
    }

    pub fn smaller_than(&mut self, max_size: usize) -> Option<&mut RtpPacket> {
        match self {
            PacketStore::Cached(v) => v.get_cached_packet_smaller_than(max_size),
            PacketStore::Uncached(_) => None,
        }
    }

    pub fn first_cached_seq_no(&self) -> Option<SeqNo> {
        match self {
            PacketStore::Cached(v) => v.first_cached_seq_no(),
            PacketStore::Uncached(_) => None,
        }
    }

    pub fn clear(&mut self) {
        match self {
            PacketStore::Cached(v) => v.clear(),
            PacketStore::Uncached(v) => v.last_packet = None,
        }
    }

    pub fn set_rtx_cache(&mut self, max_packets: usize, max_age: Duration) {
        if max_packets == 0 || max_age == Duration::ZERO {
            *self = PacketStore::Uncached(KeepLastPacket::default())
        } else {
            // Dump old cache to avoid having to deal with resizing logic inside the cache impl.
            let cache = RtxCache::new(max_packets, max_age, false);
            *self = PacketStore::Cached(cache);
        }
    }
}
