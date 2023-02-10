use crate::{FeedbackMessageType, MediaTime, RtcpType, Ssrc};

use super::{RtcpHeader, RtcpPacket};

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |V=2|P|reserved |   PT=XR=207   |             length            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                              SSRC                             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   :                         report blocks                         :
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// RFC 3611
/// <https://datatracker.ietf.org/doc/html/rfc3611#page-21>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedReport {
    pub sender_ssrc: Ssrc,
    pub blocks: Vec<ReportBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportBlock {
    ReceiverReferenceTime(ReceiverReferenceTime),
    Dlrr(Dlrr),
}

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     BT=4      |   reserved    |       block length = 2        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |              NTP timestamp, most significant word              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             NTP timestamp, least significant word              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// Receiver Reference Time Report Block
/// <https://datatracker.ietf.org/doc/html/rfc3611#section-4.4>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rrtr {
    pub ntp_time: MediaTime,
}

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     BT=5      |   reserved    |         block length          |
//   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//   |                 SSRC_1 (SSRC of first receiver)                | sub-
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ block
//   |                         last RR (LRR)                         |   1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                   delay since last RR (DLRR)                  |
//   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//   |                 SSRC_2 (SSRC of second receiver)              | sub-
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ block
//   :                               ...                             :   2
//   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

/// DLRR Report Block
/// <https://datatracker.ietf.org/doc/html/rfc3611#section-4.5>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dlrr {
    pub items: Vec<DlrrItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlrrItem {
    pub receiver_ssrc: Ssrc,
    pub last_rr_time: u32,
    pub last_rr_delay: u32,
}

impl RtcpPacket for ExtendedReport {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::ExtendedReport,
            feedback_message_type: FeedbackMessageType::NotUsed,
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        let header = 1;
        let ssrc = 1;
        let blocks: usize = self.blocks.iter().map(|b| b.len() / 4).sum();
        header + ssrc + blocks
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        let mut len = self.header().write_to(buf);

        buf[4..8].copy_from_slice(&self.sender_ssrc.to_be_bytes());
        len += 4;

        for block in self.blocks.iter() {
            len += match block {
                ReportBlock::ReceiverReferenceTime(b) => b.write_to(&mut buf[len..]),
                ReportBlock::Dlrr(b) => b.write_to(&mut buf[len..]),
            };
        }

        len
    }
}

impl ReportBlock {
    pub fn len(&self) -> usize {
        match self {
            Self::ReceiverReferenceTime(_) => ReceiverReferenceTime::len(),
            Self::Dlrr(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReceiverReferenceTime {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        // block type
        buf[0] = 4_u8;
        // reserved;
        buf[1] = 0_u8;
        // block length
        buf[2..4].copy_from_slice(&2_u16.to_be_bytes());

        // NTP timestamp
        let mt = self.ntp_time.as_ntp_64();
        buf[4..12].copy_from_slice(&mt.to_be_bytes());

        12
    }

    fn len() -> usize {
        12
    }
}

impl Dlrr {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        // block type
        buf[0] = 5_u8;
        // reserved;
        buf[1] = 0_u8;
        // block length
        let len: u16 = self.items.len() as u16 * 12_u16;
        buf[2..4].copy_from_slice(&len.to_be_bytes());

        let mut buf = &mut buf[4..];

        for item in self.items.iter() {
            buf[0..4].copy_from_slice(&item.receiver_ssrc.to_be_bytes());
            buf[4..8].copy_from_slice(&item.last_rr_time.to_be_bytes());
            buf[8..12].copy_from_slice(&item.last_rr_delay.to_be_bytes());
            buf = &mut buf[4..];
        }

        self.len()
    }

    fn len(&self) -> usize {
        4 + (self.items.len() * 4 * 3)
    }
}

impl<'a> TryFrom<&'a [u8]> for ExtendedReport {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 4 {
            return Err("Less than 4 bytes for ExtendedReport");
        }

        let sender_ssrc = u32::from_be_bytes(buf[..4].try_into().unwrap()).into();

        let mut blocks: Vec<ReportBlock> = Vec::new();
        let mut buf = &buf[4..];

        while let Ok(block) = buf.try_into() {
            let block: ReportBlock = block;
            let len = block.len();
            blocks.push(block);
            buf = &buf[len..];
        }

        Ok(ExtendedReport {
            sender_ssrc,
            blocks,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for ReportBlock {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() == 0 {
            return Err("not enough data")
        }

        let block_type: u8 = buf[0];
        match block_type {
            4 => {
                let block = ReceiverReferenceTime::try_from(buf)?;
                Ok(Self::ReceiverReferenceTime(block))
            },
            5 => {
                let block = Dlrr::try_from(buf)?;
                Ok(Self::Dlrr(block))
            },
            _ => Err("unknown block type")
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ReceiverReferenceTime {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        let ntp_time = u64::from_be_bytes(buf[4..4 + 8].try_into().unwrap());
        let ntp_time = MediaTime::from_ntp_64(ntp_time);

        Ok(ReceiverReferenceTime { ntp_time })
    }
}

impl<'a> TryFrom<&'a [u8]> for Dlrr {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        let words_per_block = 3;
        let blocks = u16::from_be_bytes(buf[2..4].try_into().unwrap()) / words_per_block;

        let mut items: Vec<DlrrItem> = Vec::with_capacity(blocks as usize);

        // move on after the header
        let mut buf = &buf[4..];

        for _ in 0..blocks {
            let receiver_ssrc = u32::from_be_bytes(buf[0..4].try_into().unwrap()).into();
            let last_rr_time = u32::from_be_bytes(buf[4..8].try_into().unwrap());
            let last_rr_delay = u32::from_be_bytes(buf[8..12].try_into().unwrap());
            items.push(DlrrItem {
                receiver_ssrc,
                last_rr_time,
                last_rr_delay,
            });
            buf = &buf[12..];
        }

        Ok(Dlrr { items })
    }
}
