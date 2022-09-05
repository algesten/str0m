use crate::{FeedbackMessageType, ReportList, RtcpHeader, RtcpPacket, RtcpType, Ssrc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Goodbye {
    pub reports: ReportList<Ssrc>,
}

impl RtcpPacket for Goodbye {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::Goodbye,
            feedback_message_type: FeedbackMessageType::SourceCount(self.reports.len() as u8),
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        // each ssrc is one word
        self.reports.len()
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        for (i, s) in self.reports.iter().enumerate() {
            (&mut buf[i * 4..(i + 1) * 4]).copy_from_slice(&s.to_be_bytes());
        }

        self.reports.len() * 4
    }
}

impl<'a> TryFrom<&'a [u8]> for Goodbye {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 4 {
            return Err("Less than 4 bytes for Goodbye");
        }

        let mut reports = ReportList::new();
        let mut buf = buf;

        let count = buf.len() / 4;

        for _ in 0..count {
            let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
            reports.push(ssrc);
            buf = &buf[4..];
        }

        Ok(Goodbye { reports })
    }
}
