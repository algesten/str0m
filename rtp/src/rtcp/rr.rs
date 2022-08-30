use std::collections::VecDeque;

use crate::{RtcpFb, RtcpHeader, Ssrc};

#[derive(Debug, PartialEq, Eq)]
pub struct ReceiverReport {
    pub ssrc: Ssrc,
    pub fraction_lost: u8,
    pub packets_lost: u32, // 24 bit
    pub max_seq: u32,
    pub jitter: u32,
    pub last_sr_time: u32,
    pub last_sr_delay: u32,
}

impl ReceiverReport {
    pub(crate) fn parse(buf: &[u8]) -> Self {
        // Receiver report shape is here
        // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.2

        let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
        let fraction_lost = buf[4];
        let packets_lost = u32::from_be_bytes([0, buf[5], buf[6], buf[7]]);
        let max_seq = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let jitter = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let last_sr_time = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let last_sr_delay = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);

        ReceiverReport {
            ssrc,
            fraction_lost,
            packets_lost,
            max_seq,
            jitter,
            last_sr_time,
            last_sr_delay,
        }
    }

    pub fn write_to(&self, buf: &mut [u8]) {
        (&mut buf[0..4]).copy_from_slice(&(*self.ssrc).to_be_bytes());
        (&mut buf[4..8]).copy_from_slice(&self.packets_lost.to_be_bytes());
        buf[4] = self.fraction_lost;
        (&mut buf[8..12]).copy_from_slice(&self.max_seq.to_be_bytes());
        (&mut buf[12..16]).copy_from_slice(&self.jitter.to_be_bytes());
        (&mut buf[16..20]).copy_from_slice(&self.last_sr_time.to_be_bytes());
        (&mut buf[20..24]).copy_from_slice(&self.last_sr_delay.to_be_bytes());
    }
}

pub fn parse_receiver_report(header: &RtcpHeader, mut buf: &[u8], queue: &mut VecDeque<RtcpFb>) {
    let count = header.fmt.count() as usize;

    for _ in 0..count {
        if buf.len() < 24 {
            return;
        }
        let report = ReceiverReport::parse(buf);
        queue.push_back(RtcpFb::ReceiverReport(report));
        buf = &buf[24..];
    }
}
