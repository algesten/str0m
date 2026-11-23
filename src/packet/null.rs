use std::alloc::Allocator;

use super::{CodecExtra, Depacketizer, PacketBuf, PacketError, Packetizer, single_packet};
use crate::allocators::copied_in;

#[derive(Debug)]
pub struct NullPacketizer;

#[derive(Debug)]
pub struct NullDepacketizer;

impl Packetizer for NullPacketizer {
    fn packetize<'a>(
        &mut self,
        _mtu: usize,
        b: &[u8],
        alloc: &'a dyn Allocator,
    ) -> Result<Vec<PacketBuf<'a>, &'a dyn Allocator>, PacketError> {
        Ok(single_packet(copied_in(b, alloc), alloc))
    }

    fn is_marker(&mut self, _data: &[u8], _previous: Option<&[u8]>, _last: bool) -> bool {
        false
    }
}

impl Depacketizer for NullDepacketizer {
    fn out_size_hint(&self, packets_size: usize) -> Option<usize> {
        Some(packets_size)
    }

    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut PacketBuf<'_>,
        _codec_extra: &mut CodecExtra,
    ) -> Result<(), PacketError> {
        out.extend_from_slice(packet);
        Ok(())
    }

    fn is_partition_head(&self, _packet: &[u8]) -> bool {
        // For rtp-mode since each packet is stand alone, it is both a partition head and tail.
        true
    }

    fn is_partition_tail(&self, _marker: bool, _packet: &[u8]) -> bool {
        // For rtp-mode since each packet is stand alone, it is both a partition head and tail.
        true
    }
}
