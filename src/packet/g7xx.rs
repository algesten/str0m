use super::{PacketError, Packetizer};

/// Packetizes G711 RTP packets.
pub type G711Packetizer = G7xxPacketizer;
/// Packetizes G722 RTP packets.
pub type G722Packetizer = G7xxPacketizer;

/// Generic packetizer for G711 and G722 packets.
#[derive(Default, Debug, Copy, Clone)]
pub struct G7xxPacketizer;

impl Packetizer for G7xxPacketizer {
    /// Payload fragments an G7xx packet across one or more byte arrays
    fn packetize(&mut self, mtu: usize, payload: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        let mut payload_data_remaining = payload.len();
        let mut payload_data_index = 0;
        let mut payloads = Vec::with_capacity(payload_data_remaining / mtu);
        while payload_data_remaining > 0 {
            let current_fragment_size = std::cmp::min(mtu, payload_data_remaining);
            payloads.push(
                payload[payload_data_index..payload_data_index + current_fragment_size].to_vec(),
            );

            payload_data_remaining -= current_fragment_size;
            payload_data_index += current_fragment_size;
        }

        Ok(payloads)
    }

    fn is_marker(&mut self, _data: &[u8], _previous: Option<&[u8]>, _last: bool) -> bool {
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
        let payloads = pck.packetize(TEST_MTU, &samples_in)?;

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
        let result = pck.packetize(1, empty)?;
        assert!(result.is_empty(), "Generated payload should be empty");

        // 0 MTU, small payload
        let result = pck.packetize(0, payload)?;
        assert_eq!(result.len(), 0, "Generated payload should be empty");

        // Positive MTU, small payload
        let result = pck.packetize(10, payload)?;
        assert_eq!(result.len(), 1, "Generated payload should be the 1");

        Ok(())
    }
}
