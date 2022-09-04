use crate::Ssrc;

use super::list::private::WordSized;
use super::{FeedbackMessageType, ReportList, RtcpHeader, RtcpPacket, RtcpType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    pub reports: ReportList<ReceptionReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceptionReport {
    pub ssrc: Ssrc,
    pub fraction_lost: u8,
    pub packets_lost: u32, // 24 bit
    pub max_seq: u32,
    pub jitter: u32,
    pub last_sr_time: u32,
    pub last_sr_delay: u32,
}

impl RtcpPacket for ReceiverReport {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::SenderReport,
            feedback_message_type: FeedbackMessageType::ReceptionReport(self.reports.len() as u8),
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        // * header: 1
        // * sender SSRC
        // * reports: x 6
        1 + 1 + 6 * self.reports.len()
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        self.header().write_to(buf);

        // TODO: Get some relevant sender SSRC in here.
        (&mut buf[4..8]).copy_from_slice(&0_u32.to_be_bytes());

        for (i, r) in self.reports.iter().enumerate() {
            r.write_to(&mut buf[8 + i * 24..]);
        }

        self.length_words() * 4
    }
}

impl WordSized for ReceptionReport {
    fn word_size(&self) -> usize {
        6
    }
}

impl ReceptionReport {
    pub(crate) fn write_to(&self, buf: &mut [u8]) {
        (&mut buf[0..4]).copy_from_slice(&self.ssrc.to_be_bytes());
        (&mut buf[4..8]).copy_from_slice(&self.packets_lost.to_be_bytes());
        buf[4] = self.fraction_lost;
        (&mut buf[8..12]).copy_from_slice(&self.max_seq.to_be_bytes());
        (&mut buf[12..16]).copy_from_slice(&self.jitter.to_be_bytes());
        (&mut buf[16..20]).copy_from_slice(&self.last_sr_time.to_be_bytes());
        (&mut buf[20..24]).copy_from_slice(&self.last_sr_delay.to_be_bytes());
    }
}
