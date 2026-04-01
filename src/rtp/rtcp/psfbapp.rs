use crate::rtp::Ssrc;

use super::RtcpType;
use super::{FeedbackMessageType, PayloadType, RtcpHeader, RtcpPacket};

/// Payload-Specific Feedback Application Layer message (PSFB FMT=15, PT=206).
///
/// Generic container for FMT=15 RTCP PSFB messages that are not REMB.
/// Carries an opaque application-dependent payload after the standard
/// sender and media SSRC fields (RFC 4585 Section 6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsfbApp {
    /// SSRC of the sender of this feedback message.
    pub sender_ssrc: Ssrc,
    /// SSRC of the media source this feedback relates to.
    pub media_ssrc: Ssrc,
    /// Application-dependent payload (after sender_ssrc and media_ssrc).
    pub payload: Vec<u8>,
}

impl RtcpPacket for PsfbApp {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::PayloadSpecificFeedback,
            feedback_message_type: FeedbackMessageType::PayloadFeedback(
                PayloadType::ApplicationLayer,
            ),
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        // 1 (RTCP header) + 2 (sender_ssrc + media_ssrc) + payload words
        let payload_words = (self.payload.len() + 3) / 4;
        1 + 2 + payload_words
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        self.header().write_to(&mut buf[..4]);
        buf[4..8].copy_from_slice(&self.sender_ssrc.to_be_bytes());
        buf[8..12].copy_from_slice(&self.media_ssrc.to_be_bytes());

        let payload_len = self.payload.len();
        buf[12..12 + payload_len].copy_from_slice(&self.payload);

        // Pad to 4-byte boundary
        let padded_payload_len = (payload_len + 3) / 4 * 4;
        for b in &mut buf[12 + payload_len..12 + padded_payload_len] {
            *b = 0;
        }

        12 + padded_payload_len
    }
}

impl<'a> TryFrom<&'a [u8]> for PsfbApp {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 8 {
            return Err("PsfbApp less than 8 bytes");
        }

        let sender_ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
        let media_ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]).into();
        let payload = buf[8..].to_vec();

        Ok(PsfbApp {
            sender_ssrc,
            media_ssrc,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psfbapp_round_trip() {
        let input = PsfbApp {
            sender_ssrc: 1.into(),
            media_ssrc: 2.into(),
            payload: vec![0x01, 0x00, 0x00, 0x44, 0xAA, 0xBB, 0xCC, 0xDD],
        };

        let mut buf = [0u8; 256];
        let written = input.write_to(&mut buf);

        // Parse back (skip 4-byte RTCP header)
        let parsed = PsfbApp::try_from(&buf[4..written]).unwrap();
        assert_eq!(input.sender_ssrc, parsed.sender_ssrc);
        assert_eq!(input.media_ssrc, parsed.media_ssrc);
        assert_eq!(input.payload, parsed.payload);
    }

    #[test]
    fn test_psfbapp_header() {
        let psfbapp = PsfbApp {
            sender_ssrc: 0.into(),
            media_ssrc: 0.into(),
            payload: vec![1, 2, 3, 4],
        };

        let header = psfbapp.header();
        assert_eq!(header.rtcp_type, RtcpType::PayloadSpecificFeedback);
    }

    #[test]
    fn test_psfbapp_non_aligned_payload() {
        // Payload not aligned to 4 bytes — should still round-trip
        let input = PsfbApp {
            sender_ssrc: 100.into(),
            media_ssrc: 200.into(),
            payload: vec![0xAA, 0xBB, 0xCC], // 3 bytes, needs 1 byte padding
        };

        let mut buf = [0u8; 256];
        let written = input.write_to(&mut buf);

        // Total should be 4 (header) + 4 (sender) + 4 (media) + 4 (padded payload) = 16
        assert_eq!(written, 16);

        let parsed = PsfbApp::try_from(&buf[4..written]).unwrap();
        assert_eq!(parsed.sender_ssrc, input.sender_ssrc);
        assert_eq!(parsed.media_ssrc, input.media_ssrc);
        // Parsed payload includes padding byte
        assert_eq!(parsed.payload.len(), 4);
        assert_eq!(&parsed.payload[..3], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(parsed.payload[3], 0); // padding
    }

    #[test]
    fn test_psfbapp_empty_payload() {
        let input = PsfbApp {
            sender_ssrc: 1.into(),
            media_ssrc: 2.into(),
            payload: vec![],
        };

        let mut buf = [0u8; 256];
        let written = input.write_to(&mut buf);
        assert_eq!(written, 12); // header + sender + media, no payload

        let parsed = PsfbApp::try_from(&buf[4..written]).unwrap();
        assert_eq!(parsed.sender_ssrc, input.sender_ssrc);
        assert_eq!(parsed.media_ssrc, input.media_ssrc);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_psfbapp_too_short_rejected() {
        let buf = [0u8; 7]; // Less than 8 bytes
        assert!(PsfbApp::try_from(&buf[..]).is_err());
    }
}
