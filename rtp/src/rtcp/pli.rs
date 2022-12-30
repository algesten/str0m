use crate::{FeedbackMessageType, PayloadType, RtcpHeader, RtcpPacket};
use crate::{RtcpType, Ssrc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pli {
    pub ssrc: Ssrc,
}

impl RtcpPacket for Pli {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::PayloadSpecificFeedback,
            feedback_message_type: FeedbackMessageType::PayloadFeedback(
                PayloadType::PictureLossIndication,
            ),
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        // header
        // sender SSRC
        // media SSRC
        3
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        self.header().write_to(&mut buf[..4]);
        buf[4..8].copy_from_slice(&[0, 0, 0, 0]); // sender SSRC
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        12
    }
}

impl<'a> TryFrom<&'a [u8]> for Pli {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 8 {
            return Err("Pli less than 8 bytes");
        }

        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]).into();

        Ok(Pli { ssrc })
    }
}
