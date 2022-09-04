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
        // * reports: x 6
        1 + 6 * self.reports.len()
    }
}

impl WordSized for ReceptionReport {
    fn word_size(&self) -> usize {
        6
    }
}
