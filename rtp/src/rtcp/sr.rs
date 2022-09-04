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

    fn write_to(&self, buf: &mut [u8]) -> usize {
        self.header().write_to(buf);

        self.sender_info.write_to(&mut buf[4..]);

        for (i, r) in self.reports.iter().enumerate() {
            r.write_to(&mut buf[28 + i * 24..]);
        }

        self.length_words() * 4
    }
}
impl SenderInfo {
    fn write_to(&self, buf: &mut [u8]) {
        // pub ssrc: Ssrc,
        // pub ntp_time: MediaTime,
        // pub rtp_time: u32,
        // pub sender_packet_count: u32,
        // pub sender_octet_count: u32,
        (&mut buf[..4]).copy_from_slice(&self.ssrc.to_be_bytes());

        let mt = self.ntp_time.as_ntp_64();
        (&mut buf[4..12]).copy_from_slice(&mt.to_be_bytes());

        (&mut buf[12..16]).copy_from_slice(&self.rtp_time.to_be_bytes());
        (&mut buf[16..20]).copy_from_slice(&self.sender_packet_count.to_be_bytes());
        (&mut buf[20..24]).copy_from_slice(&self.sender_octet_count.to_be_bytes());
    }
}
