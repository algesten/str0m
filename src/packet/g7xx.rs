use std::alloc::Allocator;

use super::{CodecExtra, Depacketizer, PacketBuf, PacketError, Packetizer};
use crate::allocators::copied_in;

/// Packetizes G711 RTP packets.
pub type G711Packetizer = G7xxPacketizer;
/// Packetizes G722 RTP packets.
pub type G722Packetizer = G7xxPacketizer;

/// Generic packetizer for G711 and G722 packets.
#[derive(Default, Debug, Copy, Clone)]
pub struct G7xxPacketizer;

impl Packetizer for G7xxPacketizer {
    /// Payload fragments an G7xx packet across one or more byte arrays
    fn packetize<'a>(
        &mut self,
        mtu: usize,
        payload: &[u8],
        alloc: &'a dyn Allocator,
    ) -> Result<Vec<PacketBuf<'a>, &'a dyn Allocator>, PacketError> {
        if payload.is_empty() || mtu == 0 {
            return Ok(Vec::new_in(alloc));
        }

        let mut payload_data_remaining = payload.len();
        let mut payload_data_index = 0;
        let mut payloads = Vec::with_capacity_in(payload_data_remaining / mtu, alloc);
        while payload_data_remaining > 0 {
            let current_fragment_size = std::cmp::min(mtu, payload_data_remaining);
            payloads.push(copied_in(
                &payload[payload_data_index..payload_data_index + current_fragment_size],
                alloc,
            ));

            payload_data_remaining -= current_fragment_size;
            payload_data_index += current_fragment_size;
        }

        Ok(payloads)
    }

    fn is_marker(&mut self, _data: &[u8], _previous: Option<&[u8]>, _last: bool) -> bool {
        false
    }

    fn marks_talkspurt(&self) -> bool {
        true
    }

    fn nackable(&self) -> bool {
        false
    }
}

/// Depacketizer for G711 packets
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct G711Depacketizer;

impl Depacketizer for G711Depacketizer {
    fn out_size_hint(&self, packets_size: usize) -> Option<usize> {
        Some(packets_size)
    }

    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut PacketBuf<'_>,
        _: &mut CodecExtra,
    ) -> Result<(), PacketError> {
        if !packet.is_empty() {
            out.extend_from_slice(packet);
        }

        Ok(())
    }

    fn is_partition_head(&self, _payload: &[u8]) -> bool {
        true
    }

    fn is_partition_tail(&self, _marker: bool, _payload: &[u8]) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use std::alloc::Global;

    use super::*;
    use crate::packet::PacketBuf;

    #[test]
    fn test_g7xx_payload() -> Result<(), PacketError> {
        let mut pck = G711Packetizer::default();

        const TEST_LEN: usize = 10000;
        const TEST_MTU: usize = 1500;

        //generate random 8-bit g722 samples
        let samples: Vec<u8> = (0..TEST_LEN).map(|_| fastrand::u8(..)).collect();

        //make a copy, for packetizer input
        let mut samples_in = vec![0u8; TEST_LEN];
        samples_in.clone_from_slice(&samples);
        let samples_in = samples_in.to_vec();

        //split our samples into payloads
        let payloads = pck.packetize(TEST_MTU, &samples_in, &Global)?;

        let outcnt = ((TEST_LEN as f64) / (TEST_MTU as f64)).ceil() as usize;
        assert_eq!(
            outcnt,
            payloads.len(),
            "Generated {} payloads instead of {}",
            payloads.len(),
            outcnt
        );
        assert_eq!(&samples, &samples_in, "Modified input samples");

        let samples_out = payloads.concat();
        assert_eq!(&samples_out, &samples_in, "Output samples don't match");

        let empty = &[];
        let payload = &[0x90, 0x90, 0x90];

        // Positive MTU, empty payload
        let result = pck.packetize(1, empty, &Global)?;
        assert!(result.is_empty(), "Generated payload should be empty");

        // 0 MTU, small payload
        let result = pck.packetize(0, payload, &Global)?;
        assert_eq!(result.len(), 0, "Generated payload should be empty");

        // Positive MTU, small payload
        let result = pck.packetize(10, payload, &Global)?;
        assert_eq!(result.len(), 1, "Generated payload should be the 1");

        Ok(())
    }

    #[test]
    fn test_g7xx_unmarshal() -> Result<(), PacketError> {
        let mut pck = G711Depacketizer;
        let mut extra = CodecExtra::None;

        // Empty packet
        let empty_bytes = &[];
        let mut out: PacketBuf = Vec::new_in(&Global);
        let result = pck.depacketize(empty_bytes, &mut out, &mut extra);
        assert!(
            result.is_ok(),
            "Result should not be err in case of empty packet"
        );

        // Normal packet
        let raw_bytes: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x90];
        let mut out: PacketBuf = Vec::new_in(&Global);
        pck.depacketize(raw_bytes, &mut out, &mut extra)?;
        assert_eq!(raw_bytes, &out, "Payload must be same");

        Ok(())
    }

    #[test]
    fn packetize_respects_mtu() -> Result<(), PacketError> {
        let payload = vec![0xABu8; 2000];
        for &mtu in &[100usize, 300, 600, 1200] {
            let mut pck = G711Packetizer::default();
            let pkts = pck.packetize(mtu, &payload, &Global)?;
            assert!(!pkts.is_empty(), "G7xx produced no packets at mtu {mtu}");
            for (i, pkt) in pkts.iter().enumerate() {
                assert!(
                    pkt.len() <= mtu,
                    "G7xx packet {i} size {} > mtu {mtu}",
                    pkt.len()
                );
            }
        }
        Ok(())
    }
}
