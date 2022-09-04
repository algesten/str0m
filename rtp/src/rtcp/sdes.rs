use crate::{FeedbackMessageType, RtcpType, Ssrc};

use super::list::private::WordSized;
use super::{pad_bytes_to_word, ReportList, RtcpHeader, RtcpPacket};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptions {
    pub reports: ReportList<Sdes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sdes {
    pub ssrc: Ssrc,
    pub values: Vec<(SdesType, String)>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SdesType {
    /// End of SDES list
    END = 0,
    /// Canonical name.
    CNAME = 1,
    /// User name
    NAME = 2,
    /// User's electronic mail address
    EMAIL = 3,
    /// User's phone number
    PHONE = 4,
    /// Geographic user location
    LOC = 5,
    /// Name of application or tool
    TOOL = 6,
    /// Notice about the source
    NOTE = 7,
    /// Private extensions
    PRIV = 8,
    /// Who knows
    Unknown,
}

impl RtcpPacket for Descriptions {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::SourceDescription,
            feedback_message_type: FeedbackMessageType::SourceCount(self.reports.len() as u8),
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        // * header: 1
        // * size-per-item * items
        1 + self.reports.iter().map(|r| r.word_size()).sum::<usize>()
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        self.header().write_to(buf);

        let mut buf = &mut buf[4..];
        let mut tot = 4;

        for r in &self.reports {
            let n = r.write_to(buf);
            buf = &mut buf[n..];
            tot += n;
        }

        tot
    }
}

impl Sdes {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        (&mut buf[..4]).copy_from_slice(&self.ssrc.to_be_bytes());
        let mut tot = 4;

        let mut buf = &mut buf[4..];
        for (t, v) in &self.values {
            let bytes = v.as_bytes();
            let len = bytes.len();

            buf[0] = *t as u8;
            buf[1] = len as u8;

            buf = &mut buf[2..];
            (&mut buf[..len]).copy_from_slice(bytes);

            tot += 2 + len;
        }

        buf[0] = SdesType::END as u8;

        buf = &mut buf[1..];
        tot += 1;

        let pad = 4 - tot % 4;
        if pad < 4 {
            for i in 0..pad {
                buf[i] = SdesType::END as u8;
            }
            tot += pad;
        }

        assert!(tot % 4 == 0, "Sdes is padded to word boundary");

        tot
    }
}

impl WordSized for Sdes {
    fn word_size(&self) -> usize {
        let byte_size = 4 + self
            .values
            .iter()
            // 2 here for 2 byte encoding of type + length
            .map(|(_, s)| 2 + s.as_bytes().len())
            .sum::<usize>();

        let padded = pad_bytes_to_word(byte_size);

        padded / 4
    }
}

impl From<u8> for SdesType {
    fn from(v: u8) -> Self {
        use SdesType::*;
        match v {
            0 => END,
            1 => CNAME,
            2 => NAME,
            3 => EMAIL,
            4 => PHONE,
            5 => LOC,
            6 => TOOL,
            7 => NOTE,
            8 => PRIV,
            _ => Unknown,
        }
    }
}
