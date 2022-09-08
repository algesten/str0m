use crate::{FeedbackMessageType, PayloadType, ReportList, RtcpHeader, RtcpPacket, RtcpType, Ssrc};

use super::list::private::WordSized;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fir {
    pub reports: ReportList<FirEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirEntry {
    pub ssrc: Ssrc,
    pub seq_no: u8,
}

impl RtcpPacket for Fir {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::PayloadSpecificFeedback,
            feedback_message_type: FeedbackMessageType::PayloadFeedback(
                PayloadType::FullIntraRequest,
            ),
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        // header
        // sender SSRC
        // media SSRC (ignored)
        // reports * FirEntry: SSRC + seqNo
        1 + 2 + self.reports.len() * 2
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        (&mut buf[0..4]).copy_from_slice(&0_u16.to_be_bytes());

        let first_ssrc = self.reports.iter().next().map(|r| *r.ssrc).unwrap_or(0);
        (&mut buf[4..8]).copy_from_slice(&first_ssrc.to_be_bytes());

        let mut buf = &mut buf[8..];
        for r in &self.reports {
            (&mut buf[0..4]).copy_from_slice(&r.ssrc.to_be_bytes());
            (&mut buf[4..8]).copy_from_slice(&[r.seq_no, 0, 0, 0]);
            buf = &mut buf[8..];
        }

        self.reports.len() * 4
    }
}

impl WordSized for FirEntry {
    fn word_size(&self) -> usize {
        2
    }
}

impl<'a> TryFrom<&'a [u8]> for Fir {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 16 {
            return Err("Fir less than 16 bytes");
        }

        let mut reports = ReportList::new();

        let mut buf = &buf[8..];
        let count = buf.len() / 8;
        let max = count.min(31);

        for _ in 0..max {
            let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
            let seq_no = buf[4];
            reports.push(FirEntry { ssrc, seq_no });
            buf = &buf[8..];
        }

        Ok(Fir { reports })
    }
}
