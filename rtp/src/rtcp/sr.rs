use std::collections::VecDeque;

use crate::{MediaTime, ReceiverReport, RtcpFb, RtcpHeader, Ssrc};

pub const LEN_SR: usize = 6 * 4;

#[derive(Debug, PartialEq, Eq)]
pub struct SenderInfo {
    pub ssrc: Ssrc,
    pub ntp_time: MediaTime,
    pub rtp_time: u32,
    pub sender_packet_count: u32,
    pub sender_octet_count: u32,
}

impl SenderInfo {
    fn parse(buf: &[u8]) -> SenderInfo {
        // Sender report shape is here
        // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1

        let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();

        let ntp_time = u64::from_be_bytes([
            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        ]);
        let ntp_time = MediaTime::from_ntp_64(ntp_time);

        // https://www.cs.columbia.edu/~hgs/rtp/faq.html#timestamp-computed
        // For video, time clock rate is fixed at 90 kHz. The timestamps generated
        // depend on whether the application can determine the frame number or not.
        // If it can or it can be sure that it is transmitting every frame with a
        // fixed frame rate, the timestamp is governed by the nominal frame rate.
        // Thus, for a 30 f/s video, timestamps would increase by 3,000 for each
        // frame, for a 25 f/s video by 3,600 for each frame.
        let rtp_time = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

        let sender_packet_count = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let sender_octet_count = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);

        SenderInfo {
            ssrc,
            ntp_time,
            rtp_time,
            sender_packet_count,
            sender_octet_count,
        }
    }

    pub(crate) fn write_to(&self, buf: &mut [u8]) -> usize {
        (&mut buf[0..4]).copy_from_slice(&self.ssrc.to_be_bytes());

        let ntp_time = self.ntp_time.as_ntp_64();
        (&mut buf[4..12]).copy_from_slice(&ntp_time.to_be_bytes());

        (&mut buf[12..16]).copy_from_slice(&self.rtp_time.to_be_bytes());
        (&mut buf[16..20]).copy_from_slice(&self.sender_packet_count.to_be_bytes());
        (&mut buf[20..24]).copy_from_slice(&self.sender_octet_count.to_be_bytes());

        LEN_SR
    }
}

pub fn parse_sender_report(header: &RtcpHeader, buf: &[u8], queue: &mut VecDeque<RtcpFb>) {
    if buf.len() < 24 {
        return;
    }

    queue.push_back(RtcpFb::SenderInfo(SenderInfo::parse(buf)));

    // Number of receiver reports.
    let count = header.fmt.count() as usize;
    let mut buf = &buf[24..];

    for _ in 0..count {
        if buf.len() < 24 {
            return;
        }
        let report = ReceiverReport::parse(buf);
        queue.push_back(RtcpFb::ReceiverReport(report));
        buf = &buf[24..];
    }
}
