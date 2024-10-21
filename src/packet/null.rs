use super::{CodecExtra, Depacketizer, PacketError, Packetizer};

#[derive(Debug)]
pub struct NullPacketizer;

#[derive(Debug)]
pub struct NullDepacketizer;

impl Packetizer for NullPacketizer {
    fn packetize(&mut self, _mtu: usize, b: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        Ok(vec![b.to_vec()])
    }

    fn is_marker(&mut self, _data: &[u8], _previous: Option<&[u8]>, _last: bool) -> bool {
        unreachable!("rtp_mode doesn't use is_marker")
    }
}

impl Depacketizer for NullDepacketizer {
    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
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
