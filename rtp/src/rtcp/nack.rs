use crate::{FeedbackMessageType, ReportList, RtcpHeader, RtcpPacket};
use crate::{RtcpType, Ssrc, TransportType};

use super::list::private::WordSized;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nack {
    pub ssrc: Ssrc,
    pub reports: ReportList<NackEntry>,
}

#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct NackEntry {
    pub pid: u16,
    pub blp: u16,
}

impl RtcpPacket for Nack {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::TransportLayerFeedback,
            feedback_message_type: FeedbackMessageType::TransportFeedback(TransportType::Nack),
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        // header
        // sender SSRC
        // media SSRC
        // 1 word per NackPair
        1 + 2 + self.reports.len()
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        (&mut buf[0..4]).copy_from_slice(&0_u16.to_be_bytes());
        (&mut buf[4..8]).copy_from_slice(&self.ssrc.to_be_bytes());
        let mut buf = &mut buf[8..];
        for r in &self.reports {
            (&mut buf[0..2]).copy_from_slice(&r.pid.to_be_bytes());
            (&mut buf[2..4]).copy_from_slice(&r.blp.to_be_bytes());
            buf = &mut buf[4..];
        }
        (self.length_words() - 1) * 4
    }
}

impl WordSized for NackEntry {
    fn word_size(&self) -> usize {
        1
    }
}

impl<'a> TryFrom<&'a [u8]> for Nack {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 12 {
            return Err("Nack less than 12 bytes");
        }

        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]).into();

        let mut reports = ReportList::new();

        let mut buf = &buf[8..];
        let count = buf.len() / 4;
        let max = count.min(31);

        for _ in 0..max {
            let pid = u16::from_be_bytes([buf[0], buf[1]]);
            let blp = u16::from_be_bytes([buf[2], buf[3]]);
            reports.push(NackEntry { pid, blp });
            buf = &buf[4..];
        }

        Ok(Nack { ssrc, reports })
    }
}
