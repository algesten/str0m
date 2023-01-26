use crate::header::extend_seq;
use crate::{FeedbackMessageType, ReportList, RtcpHeader, RtcpPacket, SeqNo};
use crate::{RtcpType, Ssrc, TransportType};

use super::list::private::WordSized;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nack {
    pub sender_ssrc: Ssrc,
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
        self.header().write_to(&mut buf[..4]);
        buf[4..8].copy_from_slice(&self.sender_ssrc.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        let mut buf = &mut buf[12..];
        for r in &self.reports {
            buf[0..2].copy_from_slice(&r.pid.to_be_bytes());
            buf[2..4].copy_from_slice(&r.blp.to_be_bytes());
            buf = &mut buf[4..];
        }
        self.length_words() * 4
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

        let sender_ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]).into();
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]).into();

        let mut reports = ReportList::new();

        let mut buf = &buf[12..];
        let count = buf.len() / 4;
        let max = count.min(31);

        for _ in 0..max {
            let pid = u16::from_be_bytes([buf[0], buf[1]]);
            let blp = u16::from_be_bytes([buf[2], buf[3]]);
            reports.push(NackEntry { pid, blp });
            buf = &buf[4..];
        }

        Ok(Nack {
            sender_ssrc,
            ssrc,
            reports,
        })
    }
}

impl NackEntry {
    pub fn into_iter(self, seq_no: SeqNo) -> impl Iterator<Item = SeqNo> {
        NackEntryIterator(self, 0, seq_no)
    }
}

pub struct NackEntryIterator(NackEntry, u16, SeqNo);

impl Iterator for NackEntryIterator {
    type Item = SeqNo;

    fn next(&mut self) -> Option<Self::Item> {
        let seq_16 = if self.1 == 0 {
            self.1 += 1;
            self.0.pid
        } else {
            loop {
                if self.1 >= 17 {
                    return None;
                }
                let i = self.1 - 1;
                self.1 += 1;
                if 1 << i & self.0.blp > 0 {
                    break self.0.pid.wrapping_add(self.1 - 1);
                }
            }
        };
        let l = extend_seq(Some(*self.2), seq_16);
        Some(l.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn nack_entry_iter() {
        // 196_618
        let seq_no: SeqNo = (65_536_u64 * 3 + 10).into();

        // 196_508
        let pid = (65_536_u32 - 100) as u16;

        println!("{seq_no:?} {pid:?}");

        // 196_509, 196_512, 196_524
        let blp = 0b1000_0000_0000_1001;

        let entry = NackEntry { pid, blp };

        let nacks: Vec<_> = entry.into_iter(seq_no).collect();

        assert_eq!(
            nacks,
            vec![196508.into(), 196509.into(), 196512.into(), 196524.into()]
        );
    }
}
