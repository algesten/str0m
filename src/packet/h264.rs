#![allow(clippy::all)]

use super::{CodecExtra, Depacketizer, MediaKind, PacketError, Packetizer};

/// Packetizes H264 RTP packets.
#[derive(Default, Debug, Clone)]
pub struct H264Packetizer {
    sps_nalu: Option<Vec<u8>>,
    pps_nalu: Option<Vec<u8>>,
}

pub const STAPA_NALU_TYPE: u8 = 24;
pub const FUA_NALU_TYPE: u8 = 28;
pub const FUB_NALU_TYPE: u8 = 29;
pub const SPS_NALU_TYPE: u8 = 7;
pub const PPS_NALU_TYPE: u8 = 8;
pub const AUD_NALU_TYPE: u8 = 9;
pub const FILLER_NALU_TYPE: u8 = 12;

pub const FUA_HEADER_SIZE: usize = 2;
pub const STAPA_HEADER_SIZE: usize = 1;
pub const STAPA_NALU_LENGTH_SIZE: usize = 2;

pub const NALU_TYPE_BITMASK: u8 = 0x1F;
pub const NALU_REF_IDC_BITMASK: u8 = 0x60;
pub const FU_START_BITMASK: u8 = 0x80;
pub const FU_END_BITMASK: u8 = 0x40;

pub const OUTPUT_STAP_AHEADER: u8 = 0x78;

pub static ANNEXB_NALUSTART_CODE: &[u8] = &[0x00, 0x00, 0x00, 0x01];

impl H264Packetizer {
    fn next_ind(nalu: &[u8], start: usize) -> (isize, isize) {
        let mut zero_count = 0;

        for (i, &b) in nalu[start..].iter().enumerate() {
            if b == 0 {
                zero_count += 1;
                continue;
            } else if b == 1 && zero_count >= 2 {
                return ((start + i - zero_count) as isize, zero_count as isize + 1);
            }
            zero_count = 0
        }
        (-1, -1)
    }

    fn emit(&mut self, nalu: &[u8], mtu: usize, payloads: &mut Vec<Vec<u8>>) {
        if nalu.is_empty() {
            return;
        }

        let nalu_type = nalu[0] & NALU_TYPE_BITMASK;
        let nalu_ref_idc = nalu[0] & NALU_REF_IDC_BITMASK;

        if nalu_type == AUD_NALU_TYPE || nalu_type == FILLER_NALU_TYPE {
            return;
        } else if nalu_type == SPS_NALU_TYPE {
            self.sps_nalu = Some(nalu.to_vec());
            return;
        } else if nalu_type == PPS_NALU_TYPE {
            self.pps_nalu = Some(nalu.to_vec());
            return;
        } else if let (Some(sps_nalu), Some(pps_nalu)) = (&self.sps_nalu, &self.pps_nalu) {
            // Pack current NALU with SPS and PPS as STAP-A
            let sps_len = (sps_nalu.len() as u16).to_be_bytes();
            let pps_len = (pps_nalu.len() as u16).to_be_bytes();

            let mut stap_a_nalu = Vec::with_capacity(1 + 2 + sps_nalu.len() + 2 + pps_nalu.len());
            stap_a_nalu.push(OUTPUT_STAP_AHEADER);
            stap_a_nalu.extend(sps_len);
            stap_a_nalu.extend_from_slice(sps_nalu);
            stap_a_nalu.extend(pps_len);
            stap_a_nalu.extend_from_slice(pps_nalu);
            if stap_a_nalu.len() <= mtu {
                payloads.push(stap_a_nalu);
            }
        }

        if self.sps_nalu.is_some() && self.pps_nalu.is_some() {
            self.sps_nalu = None;
            self.pps_nalu = None;
        }

        // Single NALU
        if nalu.len() <= mtu {
            payloads.push(nalu.to_vec());
            return;
        }

        // FU-A
        let max_fragment_size = mtu as isize - FUA_HEADER_SIZE as isize;

        // The FU payload consists of fragments of the payload of the fragmented
        // NAL unit so that if the fragmentation unit payloads of consecutive
        // FUs are sequentially concatenated, the payload of the fragmented NAL
        // unit can be reconstructed.  The NAL unit type octet of the fragmented
        // NAL unit is not included as such in the fragmentation unit payload,
        // 	but rather the information of the NAL unit type octet of the
        // fragmented NAL unit is conveyed in the F and NRI fields of the FU
        // indicator octet of the fragmentation unit and in the type field of
        // the FU header.  An FU payload MAY have any number of octets and MAY
        // be empty.

        let nalu_data = nalu;
        // According to the RFC, the first octet is skipped due to redundant information
        let mut nalu_data_index = 1;
        let nalu_data_length = nalu.len() as isize - nalu_data_index;
        let mut nalu_data_remaining = nalu_data_length;

        if std::cmp::min(max_fragment_size, nalu_data_remaining) <= 0 {
            return;
        }

        while nalu_data_remaining > 0 {
            let current_fragment_size = std::cmp::min(max_fragment_size, nalu_data_remaining);
            //out: = make([]byte, fuaHeaderSize + currentFragmentSize)
            let mut out = Vec::with_capacity(FUA_HEADER_SIZE + current_fragment_size as usize);
            // +---------------+
            // |0|1|2|3|4|5|6|7|
            // +-+-+-+-+-+-+-+-+
            // |F|NRI|  Type   |
            // +---------------+
            let b0 = FUA_NALU_TYPE | nalu_ref_idc;
            out.push(b0);

            // +---------------+
            //|0|1|2|3|4|5|6|7|
            //+-+-+-+-+-+-+-+-+
            //|S|E|R|  Type   |
            //+---------------+

            let mut b1 = nalu_type;
            if nalu_data_remaining == nalu_data_length {
                // Set start bit
                b1 |= 1 << 7;
            } else if nalu_data_remaining - current_fragment_size == 0 {
                // Set end bit
                b1 |= 1 << 6;
            }
            out.push(b1);

            out.extend_from_slice(
                &nalu_data
                    [nalu_data_index as usize..(nalu_data_index + current_fragment_size) as usize],
            );
            payloads.push(out);

            nalu_data_remaining -= current_fragment_size;
            nalu_data_index += current_fragment_size;
        }
    }
}

impl Packetizer for H264Packetizer {
    /// Payload fragments a H264 packet across one or more byte arrays
    fn packetize(&mut self, mtu: usize, payload: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        let mut payloads = vec![];

        let (mut next_ind_start, mut next_ind_len) = H264Packetizer::next_ind(payload, 0);
        if next_ind_start == -1 {
            self.emit(payload, mtu, &mut payloads);
        } else {
            while next_ind_start != -1 {
                let prev_start = (next_ind_start + next_ind_len) as usize;
                let (next_ind_start2, next_ind_len2) =
                    H264Packetizer::next_ind(payload, prev_start);
                next_ind_start = next_ind_start2;
                next_ind_len = next_ind_len2;
                if next_ind_start != -1 {
                    self.emit(
                        &payload[prev_start..next_ind_start as usize],
                        mtu,
                        &mut payloads,
                    );
                } else {
                    // Emit until end of stream, no end indicator found
                    self.emit(&payload[prev_start..], mtu, &mut payloads);
                }
            }
        }

        Ok(payloads)
    }
}

/// Depacketizes H264 RTP packets.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct H264Depacketizer {
    pub is_avc: bool,
    fua_buffer: Option<Vec<u8>>,
}

impl Depacketizer for H264Depacketizer {
    /// depacketize parses the passed byte slice and stores the result in the H264Packet this method is called upon
    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
        _: &mut CodecExtra,
    ) -> Result<(), PacketError> {
        if packet.len() <= 2 {
            return Err(PacketError::ErrShortPacket);
        }

        // NALU Types
        // https://tools.ietf.org/html/rfc6184#section-5.4
        let b0 = packet[0];
        let nalu_type = b0 & NALU_TYPE_BITMASK;

        match nalu_type {
            1..=23 => {
                if self.is_avc {
                    out.extend_from_slice(&(packet.len() as u32).to_be_bytes());
                } else {
                    out.extend_from_slice(ANNEXB_NALUSTART_CODE);
                }
                out.extend_from_slice(packet);
                Ok(())
            }
            STAPA_NALU_TYPE => {
                let mut curr_offset = STAPA_HEADER_SIZE;
                while curr_offset < packet.len() {
                    let nalu_size =
                        ((packet[curr_offset] as usize) << 8) | packet[curr_offset + 1] as usize;
                    curr_offset += STAPA_NALU_LENGTH_SIZE;

                    if packet.len() < curr_offset + nalu_size {
                        return Err(PacketError::StapASizeLargerThanBuffer(
                            nalu_size,
                            packet.len() - curr_offset,
                        ));
                    }

                    if self.is_avc {
                        out.extend_from_slice(&(nalu_size as u32).to_be_bytes());
                    } else {
                        out.extend_from_slice(ANNEXB_NALUSTART_CODE);
                    }
                    out.extend_from_slice(&packet[curr_offset..curr_offset + nalu_size]);
                    curr_offset += nalu_size;
                }

                Ok(())
            }
            FUA_NALU_TYPE => {
                if packet.len() < FUA_HEADER_SIZE as usize {
                    return Err(PacketError::ErrShortPacket);
                }

                if self.fua_buffer.is_none() {
                    self.fua_buffer = Some(Vec::new());
                }

                if let Some(fua_buffer) = &mut self.fua_buffer {
                    fua_buffer.extend_from_slice(&packet[FUA_HEADER_SIZE as usize..]);
                }

                let b1 = packet[1];
                if b1 & FU_END_BITMASK != 0 {
                    let nalu_ref_idc = b0 & NALU_REF_IDC_BITMASK;
                    let fragmented_nalu_type = b1 & NALU_TYPE_BITMASK;

                    if let Some(fua_buffer) = self.fua_buffer.take() {
                        if self.is_avc {
                            out.extend_from_slice(&((fua_buffer.len() + 1) as u32).to_be_bytes());
                        } else {
                            out.extend_from_slice(ANNEXB_NALUSTART_CODE);
                        }
                        out.push(nalu_ref_idc | fragmented_nalu_type);
                        out.extend_from_slice(&fua_buffer);
                    }

                    Ok(())
                } else {
                    Ok(())
                }
            }
            _ => Err(PacketError::NaluTypeIsNotHandled(nalu_type)),
        }
    }

    /// is_partition_head checks if this is the head of a packetized nalu stream.
    fn is_partition_head(&self, packet: &[u8]) -> bool {
        if packet.len() < 2 {
            return false;
        }

        if packet[0] & NALU_TYPE_BITMASK == FUA_NALU_TYPE
            || packet[0] & NALU_TYPE_BITMASK == FUB_NALU_TYPE
        {
            (packet[1] & FU_START_BITMASK) != 0
        } else {
            true
        }
    }

    fn is_partition_tail(&self, marker: bool, _packet: &[u8]) -> bool {
        marker
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_h264_payload() -> Result<(), PacketError> {
        let empty = &[];
        let small_payload = &[0x90, 0x90, 0x90];
        let multiple_payload = &[0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x01, 0x90];
        let large_payload = &[
            0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15,
        ];
        let large_payload_packetized = vec![
            &[0x1c, 0x80, 0x01, 0x02, 0x03],
            &[0x1c, 0x00, 0x04, 0x05, 0x06],
            &[0x1c, 0x00, 0x07, 0x08, 0x09],
            &[0x1c, 0x00, 0x10, 0x11, 0x12],
            &[0x1c, 0x40, 0x13, 0x14, 0x15],
        ];

        let mut pck = H264Packetizer::default();

        // Positive MTU, empty payload
        let result = pck.packetize(1, empty)?;
        assert!(result.is_empty(), "Generated payload should be empty");

        // 0 MTU, small payload
        let result = pck.packetize(0, small_payload)?;
        assert_eq!(result.len(), 0, "Generated payload should be empty");

        // Positive MTU, small payload
        let result = pck.packetize(1, small_payload)?;
        assert_eq!(result.len(), 0, "Generated payload should be empty");

        // Positive MTU, small payload
        let result = pck.packetize(5, small_payload)?;
        assert_eq!(result.len(), 1, "Generated payload should be the 1");
        assert_eq!(
            result[0].len(),
            small_payload.len(),
            "Generated payload should be the same size as original payload size"
        );

        // Multiple NALU in a single payload
        let result = pck.packetize(5, multiple_payload)?;
        assert_eq!(result.len(), 2, "2 nal units should be broken out");
        for i in 0..2 {
            assert_eq!(
                result[i].len(),
                1,
                "Payload {} of 2 is packed incorrectly",
                i + 1,
            );
        }

        // Large Payload split across multiple RTP Packets
        let result = pck.packetize(5, large_payload)?;
        assert_eq!(
            result, large_payload_packetized,
            "FU-A packetization failed"
        );

        // Nalu type 9 or 12
        let small_payload2 = &[0x09, 0x00, 0x00];
        let result = pck.packetize(5, small_payload2)?;
        assert_eq!(result.len(), 0, "Generated payload should be empty");

        Ok(())
    }

    #[test]
    fn test_h264_packet_unmarshal() -> Result<(), PacketError> {
        let single_payload = &[0x90, 0x90, 0x90];
        let single_payload_unmarshaled = &[0x00, 0x00, 0x00, 0x01, 0x90, 0x90, 0x90];
        let single_payload_unmarshaled_avc = &[0x00, 0x00, 0x00, 0x03, 0x90, 0x90, 0x90];

        let large_payload = &[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        ];
        let large_payload_avc = &[
            0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        ];
        let large_payload_packetized = vec![
            &[0x1c, 0x80, 0x01, 0x02, 0x03],
            &[0x1c, 0x00, 0x04, 0x05, 0x06],
            &[0x1c, 0x00, 0x07, 0x08, 0x09],
            &[0x1c, 0x00, 0x10, 0x11, 0x12],
            &[0x1c, 0x40, 0x13, 0x14, 0x15],
        ];

        let single_payload_multi_nalu = &[
            0x78, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40,
            0x3c, 0x22, 0x11, 0xa8, 0x00, 0x05, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
        ];
        let single_payload_multi_nalu_unmarshaled = &[
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a,
            0x40, 0x3c, 0x22, 0x11, 0xa8, 0x00, 0x00, 0x00, 0x01, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
        ];
        let single_payload_multi_nalu_unmarshaled_avc = &[
            0x00, 0x00, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a,
            0x40, 0x3c, 0x22, 0x11, 0xa8, 0x00, 0x00, 0x00, 0x05, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
        ];

        let incomplete_single_payload_multi_nalu = &[
            0x78, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40,
            0x3c, 0x22, 0x11,
        ];

        let mut pkt = H264Depacketizer::default();
        let mut avc_pkt = H264Depacketizer {
            is_avc: true,
            ..Default::default()
        };

        let mut extra = CodecExtra::None;

        let data = &[];
        let mut out = Vec::new();
        let result = pkt.depacketize(data, &mut out, &mut extra);
        assert!(result.is_err(), "Unmarshal did not fail on nil payload");

        let data = &[0x00, 0x00];
        let mut out = Vec::new();
        let result = pkt.depacketize(data, &mut out, &mut extra);
        assert!(
            result.is_err(),
            "Unmarshal accepted a packet that is too small for a payload and header"
        );

        let data = &[0xFF, 0x00, 0x00];
        let mut out = Vec::new();
        let result = pkt.depacketize(data, &mut out, &mut extra);
        assert!(
            result.is_err(),
            "Unmarshal accepted a packet with a NALU Type we don't handle"
        );

        let mut out = Vec::new();
        let result = pkt.depacketize(incomplete_single_payload_multi_nalu, &mut out, &mut extra);
        assert!(
            result.is_err(),
            "Unmarshal accepted a STAP-A packet with insufficient data"
        );

        let mut out = Vec::new();
        pkt.depacketize(single_payload, &mut out, &mut extra)?;
        assert_eq!(
            out, single_payload_unmarshaled,
            "Unmarshaling a single payload shouldn't modify the payload"
        );

        let mut out = Vec::new();
        avc_pkt.depacketize(single_payload, &mut out, &mut extra)?;
        assert_eq!(
            out, single_payload_unmarshaled_avc,
            "Unmarshaling a single payload into avc stream shouldn't modify the payload"
        );

        let mut large_out = Vec::new();
        for p in &large_payload_packetized {
            pkt.depacketize(*p, &mut large_out, &mut extra)?;
        }
        assert_eq!(
            large_out, large_payload,
            "Failed to unmarshal a large payload"
        );

        let mut large_out_avc = Vec::new();
        for p in &large_payload_packetized {
            avc_pkt.depacketize(*p, &mut large_out_avc, &mut extra)?;
        }
        assert_eq!(
            large_out_avc, large_payload_avc,
            "Failed to unmarshal a large payload into avc stream"
        );

        let mut out = Vec::new();
        pkt.depacketize(single_payload_multi_nalu, &mut out, &mut extra)?;
        assert_eq!(
            out, single_payload_multi_nalu_unmarshaled,
            "Failed to unmarshal a single packet with multiple NALUs"
        );

        let mut out = Vec::new();
        avc_pkt.depacketize(single_payload_multi_nalu, &mut out, &mut extra)?;
        assert_eq!(
            out, single_payload_multi_nalu_unmarshaled_avc,
            "Failed to unmarshal a single packet with multiple NALUs into avc stream"
        );

        Ok(())
    }

    #[test]
    fn test_h264_partition_head_checker_is_partition_head() -> Result<(), PacketError> {
        let h264 = H264Depacketizer::default();
        let empty_nalu = &[];
        assert!(
            !h264.is_partition_head(empty_nalu),
            "empty nalu must not be a partition head"
        );

        let single_nalu = &[1, 0];
        assert!(
            h264.is_partition_head(single_nalu),
            "single nalu must be a partition head"
        );

        let stapa_nalu = &[STAPA_NALU_TYPE, 0];
        assert!(
            h264.is_partition_head(stapa_nalu),
            "stapa nalu must be a partition head"
        );

        let fua_start_nalu = &[FUA_NALU_TYPE, FU_START_BITMASK];
        assert!(
            h264.is_partition_head(fua_start_nalu),
            "fua start nalu must be a partition head"
        );

        let fua_end_nalu = &[FUA_NALU_TYPE, FU_END_BITMASK];
        assert!(
            !h264.is_partition_head(fua_end_nalu),
            "fua end nalu must not be a partition head"
        );

        let fub_start_nalu = &[FUB_NALU_TYPE, FU_START_BITMASK];
        assert!(
            h264.is_partition_head(fub_start_nalu),
            "fub start nalu must be a partition head"
        );

        let fub_end_nalu = &[FUB_NALU_TYPE, FU_END_BITMASK];
        assert!(
            !h264.is_partition_head(fub_end_nalu),
            "fub end nalu must not be a partition head"
        );

        Ok(())
    }

    #[test]
    fn test_h264_packetizer_payload_sps_and_pps_handling() -> Result<(), PacketError> {
        let mut pck = H264Packetizer::default();
        let expected: Vec<&[u8]> = vec![
            &[
                0x78, 0x00, 0x03, 0x07, 0x00, 0x01, 0x00, 0x03, 0x08, 0x02, 0x03,
            ],
            &[0x05, 0x04, 0x05],
        ];

        // When packetizing SPS and PPS are emitted with following NALU
        let res = pck.packetize(1500, &[0x07, 0x00, 0x01])?;
        assert!(res.is_empty(), "Generated payload should be empty");

        let res = pck.packetize(1500, &[0x08, 0x02, 0x03])?;
        assert!(res.is_empty(), "Generated payload should be empty");

        let actual = pck.packetize(1500, &[0x05, 0x04, 0x05])?;
        assert_eq!(actual, expected, "SPS and PPS aren't packed together");

        Ok(())
    }
}
