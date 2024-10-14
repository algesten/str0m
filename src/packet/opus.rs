use super::{CodecExtra, Depacketizer, MediaKind, PacketError, Packetizer};

/// Packetizes Opus RTP packets.
#[derive(Debug, Copy, Clone)]
pub struct OpusPacketizer {
    // stores if a marker was previously set
    marker: bool,
    use_dtx: bool,
}

impl OpusPacketizer {
    pub fn new(use_dtx: bool) -> Self {
        Self {
            marker: false,
            use_dtx,
        }
    }
}

impl Packetizer for OpusPacketizer {
    fn packetize(&mut self, mtu: usize, payload: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        let mut out = vec![];

        let mut cur = 0;
        while cur < payload.len() {
            let min = mtu.min(payload.len() - cur);
            out.push(payload[cur..(cur + min)].to_vec());
            cur += mtu;
        }

        Ok(out)
    }

    fn is_marker(&mut self, data: &[u8], previous: Option<&[u8]>, last: bool) -> bool {
        if !self.use_dtx {
            return false;
        }
        // any non silenced packet would generally have more than 2 byts
        let mut is_marker = data.len() > 2;

        match self.marker {
            true => {
                if !is_marker {
                    self.marker = false;
                }
                is_marker = false;
            }
            false => {
                if is_marker {
                    self.marker = true;
                }
            }
        }
        is_marker
    }
}

/// Depacketizes Opus RTP packets.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct OpusDepacketizer;

impl Depacketizer for OpusDepacketizer {
    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
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
    use super::*;

    #[test]
    fn test_opus_unmarshal() -> Result<(), PacketError> {
        let mut pck = OpusDepacketizer;
        let mut extra = CodecExtra::None;

        // Empty packet
        let empty_bytes = &[];
        let mut out = Vec::new();
        let result = pck.depacketize(empty_bytes, &mut out, &mut extra);
        assert!(
            result.is_ok(),
            "Result should not be err in case of empty packet"
        );

        // Normal packet
        let raw_bytes: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x90];
        let mut out = Vec::new();
        pck.depacketize(raw_bytes, &mut out, &mut extra)?;
        assert_eq!(raw_bytes, &out, "Payload must be same");

        Ok(())
    }

    #[test]
    fn test_opus_payload() -> Result<(), PacketError> {
        let mut pck = OpusPacketizer::new(true);
        let empty = &[];
        let payload = &[0x90, 0x90, 0x90];

        // Positive MTU, empty payload
        let result = pck.packetize(1, empty)?;
        assert!(result.is_empty(), "Generated payload should be empty");

        // Positive MTU, small payload
        let result = pck.packetize(1, payload)?;
        assert_eq!(result.len(), 3, "Generated payload should be 3");

        // Positive MTU, small payload
        let result = pck.packetize(2, payload)?;
        assert_eq!(result.len(), 2, "Generated payload should be the 2");

        Ok(())
    }

    #[test]
    fn test_opus_packetizer_dtx() -> Result<(), PacketError> {
        // packetizer with dtx on
        let mut pck = OpusPacketizer::new(true);

        let payload = &[0x90, 0x90, 0x90];

        // Start of talking spurt, marker bit is set.
        let is_marker = pck.is_marker(payload, None, false);
        assert!(is_marker);
        assert!(pck.marker);

        // More talking so is_marker should be false.
        let is_marker = pck.is_marker(payload, None, false);
        assert!(!is_marker);
        assert!(pck.marker);

        // silence packet inserted, internal packetizer state should be reset.
        let is_marker = pck.is_marker(&[], None, false);
        assert!(!is_marker);
        assert!(!pck.marker);

        // talking start again, marker bit is set.
        let is_marker = pck.is_marker(payload, None, false);
        assert!(is_marker);
        assert!(pck.marker);

        let mut pck = OpusPacketizer::new(false);

        // Start of talking spurt, since dtx is false marker should be false
        let is_marker = pck.is_marker(payload, None, false);
        assert!(!is_marker);
        assert!(!pck.marker);

        Ok(())
    }

    #[test]
    fn test_opus_is_partition_head() -> Result<(), PacketError> {
        let opus = OpusDepacketizer;
        //"NormalPacket"
        assert!(
            opus.is_partition_head(&[0x00, 0x00]),
            "All OPUS RTP packet should be the head of a new partition"
        );

        Ok(())
    }
}
