/// Filter RTCP compound packet to only include allowed block types.
///
/// Walks the compound packet using 4-byte RTCP common headers, keeping
/// only types relevant for BWE analysis and stripping PII-containing
/// blocks (SDES) and application-specific blocks (APP).
///
/// This matches WebRTC's `RemoveNonAllowlistedRtcpBlocks()`.
///
/// **Allowed** (kept):
/// - 200: Sender Report (SR)
/// - 201: Receiver Report (RR)
/// - 203: BYE
/// - 205: RTPFB (Transport-layer Feedback — NACK, TWCC, etc.)
/// - 206: PSFB (Payload-specific Feedback — PLI, FIR, etc.)
/// - 207: XR (Extended Reports)
///
/// **Filtered out** (removed):
/// - 202: SDES (contains CNAME, potentially PII)
/// - 204: APP (application-specific, not useful for BWE analysis)
/// - All other unknown types
pub fn filter_rtcp(raw_rtcp: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(raw_rtcp.len());
    let mut offset = 0;

    while offset + 4 <= raw_rtcp.len() {
        let pt = raw_rtcp[offset + 1];
        let length_words = u16::from_be_bytes([raw_rtcp[offset + 2], raw_rtcp[offset + 3]]);
        let block_len = (length_words as usize + 1) * 4;

        if offset + block_len > raw_rtcp.len() {
            break; // Truncated block — stop parsing
        }

        match pt {
            // SR, RR, BYE, RTPFB, PSFB, XR — keep
            200 | 201 | 203 | 205 | 206 | 207 => {
                result.extend_from_slice(&raw_rtcp[offset..offset + block_len]);
            }
            // SDES (202), APP (204), unknown — strip
            _ => {}
        }

        offset += block_len;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rtcp_block(pt: u8, payload_words: u16) -> Vec<u8> {
        let mut block = vec![0x80, pt]; // V=2, P=0, RC=0
        block.extend_from_slice(&payload_words.to_be_bytes());
        // Fill payload (payload_words * 4 bytes, since length field is total words - 1)
        block.resize((payload_words as usize + 1) * 4, 0);
        block
    }

    #[test]
    fn keeps_sr_rr_bye() {
        let mut compound = Vec::new();
        compound.extend(make_rtcp_block(200, 6)); // SR
        compound.extend(make_rtcp_block(201, 1)); // RR
        compound.extend(make_rtcp_block(203, 0)); // BYE

        let filtered = filter_rtcp(&compound);
        assert_eq!(filtered, compound);
    }

    #[test]
    fn strips_sdes_and_app() {
        let sr = make_rtcp_block(200, 6);
        let sdes = make_rtcp_block(202, 2);
        let app = make_rtcp_block(204, 3);
        let rr = make_rtcp_block(201, 1);

        let mut compound = Vec::new();
        compound.extend(&sr);
        compound.extend(&sdes);
        compound.extend(&app);
        compound.extend(&rr);

        let filtered = filter_rtcp(&compound);

        let mut expected = Vec::new();
        expected.extend(&sr);
        expected.extend(&rr);
        assert_eq!(filtered, expected);
    }

    #[test]
    fn keeps_feedback_and_xr() {
        let mut compound = Vec::new();
        compound.extend(make_rtcp_block(205, 2)); // RTPFB
        compound.extend(make_rtcp_block(206, 1)); // PSFB
        compound.extend(make_rtcp_block(207, 3)); // XR

        let filtered = filter_rtcp(&compound);
        assert_eq!(filtered, compound);
    }

    #[test]
    fn empty_input() {
        assert!(filter_rtcp(&[]).is_empty());
    }

    #[test]
    fn truncated_block_stops_parsing() {
        let mut compound = make_rtcp_block(200, 6); // 28 bytes
        compound.truncate(20); // Truncate the block

        let filtered = filter_rtcp(&compound);
        assert!(filtered.is_empty()); // Block was too short, nothing kept
    }
}
