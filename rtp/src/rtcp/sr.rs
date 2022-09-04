use crate::{FeedbackMessageType, MediaTime, RtcpType, Ssrc};

use super::{ReceptionReport, ReportList, RtcpHeader, RtcpPacket};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    pub sender_info: SenderInfo,
    pub reports: ReportList<ReceptionReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderInfo {
    pub ssrc: Ssrc,
    pub ntp_time: MediaTime,
    pub rtp_time: u32,
    pub sender_packet_count: u32,
    pub sender_octet_count: u32,
}

impl RtcpPacket for SenderReport {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::SenderReport,
            feedback_message_type: FeedbackMessageType::ReceptionReport(self.reports.len() as u8),
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        // * header: 1
        // * sender info: 6
        // * reports: x 6
        1 + 6 + 6 * self.reports.len()
    }
}
