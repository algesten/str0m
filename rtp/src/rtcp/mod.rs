mod header;
use std::collections::VecDeque;

pub use header::{RtcpHeader, RtcpType};

mod list;
pub(crate) use list::ReportList;

mod fmt;
pub use fmt::{FeedbackMessageType, PayloadType, TransportType};

mod sr;
pub use sr::{SenderInfo, SenderReport};

mod rr;
pub use rr::{ReceiverReport, ReceptionReport};

mod sdes;
pub use sdes::{Descriptions, Sdes, SdesType};

mod bb;
pub use bb::Goodbye;

use crate::Ssrc;

use self::list::private::WordSized;

pub trait RtcpPacket {
    /// The...
    fn header(&self) -> RtcpHeader;

    /// Length of entire RTCP packet (including header) in words (4 bytes).
    fn length_words(&self) -> usize;

    /// Write this packet to the buffer.
    ///
    /// Panics if the buffer doesn't have capacity to hold length_words * 4 bytes.
    fn write_to(&self, buf: &mut [u8]) -> usize;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpFb {
    SenderReport(SenderReport),
    ReceiverReport(ReceiverReport),
    SourceDescription(Descriptions),
    Goodbye(Goodbye),
}

impl RtcpFb {
    pub fn read_packet(buf: &[u8]) -> Result<VecDeque<RtcpFb>, &'static str> {
        let mut feedback = VecDeque::new();

        let mut buf = buf;
        loop {
            if buf.is_empty() {
                break;
            }

            let header: RtcpHeader = buf.try_into()?;
            let has_padding = buf[0] & 0b00_1_00000 > 0;
            let full_length = header.length_words() * 4;

            println!("{:?}", header);

            let unpadded_length = if has_padding {
                let pad = buf[full_length - 1] as usize;
                if full_length < pad {
                    return Err("buf.len() is less than padding");
                }
                full_length - pad
            } else {
                full_length
            };

            let fb = (&buf[..unpadded_length]).try_into()?;
            feedback.push_back(fb);

            buf = &buf[full_length..];
        }

        Ok(feedback)
    }

    pub fn write_packet(feedback: &mut VecDeque<RtcpFb>, buf: &mut [u8], pad_to: usize) -> usize {
        assert!(pad_to > 0, "pad_to must be more than 0");
        assert_eq!(pad_to % 4, 0, "pad_to is on a word boundary");

        // Total length, in bytes, shrunk to be on the pad_to boundary.
        let mut total_len = buf.len();
        total_len -= total_len % pad_to;

        // Capacity in words
        let word_capacity = total_len / 4;

        // Pack RTCP feedback packets. Merge together ones of the same type.
        RtcpFb::pack(feedback, word_capacity);

        let mut offset = 0;
        let mut offset_prev = 0;
        while let Some(fb) = feedback.front() {
            // Length of next item.
            let item_len = fb.length_words() * 4;

            // Capacity left in the buffer.
            let capacity = total_len - offset;
            if capacity < item_len {
                break;
            }

            // We definitely can fit the next RTCP item.
            let fb = feedback.pop_front().unwrap();
            let written = fb.write_to(&mut buf[offset..]);

            assert_eq!(written, item_len, "length_words equals write_to length");

            // Move offsets for the amount written.
            offset_prev = offset;
            offset += item_len;
        }

        // Check if there is padding needed to fill up to pad_to.
        let pad = pad_to - offset % pad_to;
        if offset > 0 && pad_to > 1 && pad < pad_to {
            for i in 0..pad {
                buf[offset + i] = 0;
            }
            offset += pad;

            // In a compound RTCP packet, padding is only
            // required on one individual packet because the compound packet is
            // encrypted as a whole .  Thus, padding MUST only be added to the
            // last individual packet, and if padding is added to that packet,
            // the padding bit MUST be set only on that packet.
            buf[offset - 1] = pad as u8;
            let header = &mut buf[offset_prev..];

            // Add padding bytes on to the total length of the packet.
            let mut words_less_one = u16::from_be_bytes([header[2], header[3]]);
            words_less_one += pad as u16 / 4;
            (&mut header[2..4]).copy_from_slice(&words_less_one.to_be_bytes());

            // Toggle padding bit
            buf[offset_prev] |= 0b00_1_00000;
        }

        offset
    }

    fn merge(&mut self, other: &mut RtcpFb, words_left: usize) -> bool {
        match (self, other) {
            // Stack receiver reports into sender reports.
            (RtcpFb::SenderReport(sr), RtcpFb::ReceiverReport(rr)) => {
                let n = sr.reports.append_all_possible(&mut rr.reports, words_left);
                n > 0
            }

            // Stack receiver reports.
            (RtcpFb::ReceiverReport(r1), RtcpFb::ReceiverReport(r2)) => {
                let n = r1.reports.append_all_possible(&mut r2.reports, words_left);
                n > 0
            }

            // Stack source descriptions.
            (RtcpFb::SourceDescription(s1), RtcpFb::SourceDescription(s2)) => {
                let n = s1.reports.append_all_possible(&mut s2.reports, words_left);
                n > 0
            }

            // Stack source descriptions.
            (RtcpFb::Goodbye(g1), RtcpFb::Goodbye(g2)) => {
                let n = g1.reports.append_all_possible(&mut g2.reports, words_left);
                n > 0
            }

            // No merge possible
            _ => false,
        }
    }

    fn is_full(&self) -> bool {
        match self {
            RtcpFb::SenderReport(v) => v.reports.is_full(),
            RtcpFb::ReceiverReport(v) => v.reports.is_full(),
            RtcpFb::SourceDescription(v) => v.reports.is_full(),
            RtcpFb::Goodbye(v) => v.reports.is_full(),
        }
    }

    /// If this RtcpFb contains no reports (anymore). This can happen after
    /// merging reports together.
    fn is_empty(&self) -> bool {
        match self {
            // A SenderReport always has, at least, the SenderInfo part.
            RtcpFb::SenderReport(_) => false,
            // ReceiverReport can become empty.
            RtcpFb::ReceiverReport(v) => v.reports.is_empty(),
            // SourceDescription can become empty.
            RtcpFb::SourceDescription(v) => v.reports.is_empty(),
            // Goodbye can become empty,
            RtcpFb::Goodbye(v) => v.reports.is_empty(),
        }
    }

    fn pack(feedback: &mut VecDeque<Self>, mut word_capacity: usize) {
        // Index into feedback of item we are to pack into.
        let mut i = 0;
        let len = feedback.len();

        'outer: loop {
            // If we reach last element, there is no more packing to do.
            if i == len - 1 {
                break;
            }

            // fb_a is the item we are merging items into.
            // SAFETY: We're never going to have i and j referencing the same item in feedback.
            let fb_a = unsafe {
                let fb_a_ptr = &mut feedback[i] as *mut RtcpFb;
                &mut *fb_a_ptr
            };

            // if we mananage to merge anything into fb_a.
            let mut any_change = false;

            // j goes from the item _after_ i and indexes fb_b.
            for j in i + 1..len {
                // if fb_a is full (or empty), we don't want to move any more elements into fb_a.
                if fb_a.is_full() || fb_a.is_empty() {
                    break;
                }

                // abort if fb_a won't fit in the spare capacity.
                if word_capacity < fb_a.length_words() {
                    break 'outer;
                }

                // the item we are going to merge from into fb_a.
                let fb_b = &mut feedback[j];

                // amount of capacity (in words) left to fill.
                let capacity = word_capacity - fb_a.length_words();

                // attempt to merge some elements into fb_a from fb_b.
                let did_merge = fb_a.merge(fb_b, capacity);
                any_change |= did_merge;
            }

            if !any_change {
                word_capacity -= fb_a.length_words();
                i += 1;
            }
        }

        // prune empty
        feedback.retain(|f| !f.is_empty());
    }
}

impl RtcpPacket for RtcpFb {
    fn header(&self) -> RtcpHeader {
        match self {
            RtcpFb::SenderReport(v) => v.header(),
            RtcpFb::ReceiverReport(v) => v.header(),
            RtcpFb::SourceDescription(v) => v.header(),
            RtcpFb::Goodbye(v) => v.header(),
        }
    }

    fn length_words(&self) -> usize {
        match self {
            RtcpFb::SenderReport(v) => v.length_words(),
            RtcpFb::ReceiverReport(v) => v.length_words(),
            RtcpFb::SourceDescription(v) => v.length_words(),
            RtcpFb::Goodbye(v) => v.length_words(),
        }
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        match self {
            RtcpFb::SenderReport(v) => v.write_to(buf),
            RtcpFb::ReceiverReport(v) => v.write_to(buf),
            RtcpFb::SourceDescription(v) => v.write_to(buf),
            RtcpFb::Goodbye(v) => v.write_to(buf),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for RtcpFb {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        let header: RtcpHeader = buf.try_into()?;

        // By constraining the length, all subparsing can go
        // until they exhaust the buffer length. This presupposes
        // padding is removed from the input.
        let buf = &buf[4..];

        Ok(match header.rtcp_type() {
            RtcpType::SenderReport => RtcpFb::SenderReport(buf.try_into()?),
            RtcpType::ReceiverReport => RtcpFb::ReceiverReport(buf.try_into()?),
            RtcpType::SourceDescription => RtcpFb::SourceDescription(buf.try_into()?),
            RtcpType::Goodbye => RtcpFb::Goodbye(buf.try_into()?),
            RtcpType::ApplicationDefined => todo!(),
            RtcpType::TransportLayerFeedback => todo!(),
            RtcpType::PayloadSpecificFeedback => todo!(),
            RtcpType::ExtendedReport => todo!(),
        })
    }
}

impl WordSized for Ssrc {
    fn word_size(&self) -> usize {
        1
    }
}

/// Pad up to the next word (4 byte) boundary.
fn pad_bytes_to_word(n: usize) -> usize {
    let pad = 4 - n % 4;
    if pad == 4 {
        n
    } else {
        n + pad
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::MediaTime;

    #[test]
    fn pack_sr_4_rr() {
        let now = MediaTime::now();
        let mut queue = VecDeque::new();
        queue.push_back(sr(1, now));
        queue.push_back(rr(3));
        queue.push_back(rr(4));
        queue.push_back(rr(5));

        RtcpFb::pack(&mut queue, 350);

        assert_eq!(queue.len(), 1);

        let sr = match queue.pop_front().unwrap() {
            RtcpFb::SenderReport(v) => v,
            _ => unreachable!(),
        };

        assert_eq!(sr.reports.len(), 4);
        let mut iter = sr.reports.iter();
        assert_eq!(iter.next().unwrap(), &report(2));
        assert_eq!(iter.next().unwrap(), &report(3));
        assert_eq!(iter.next().unwrap(), &report(4));
        assert_eq!(iter.next().unwrap(), &report(5));
    }

    #[test]
    fn pack_4_rr() {
        let mut queue = VecDeque::new();
        queue.push_back(rr(1));
        queue.push_back(rr(2));
        queue.push_back(rr(3));
        queue.push_back(rr(4));

        RtcpFb::pack(&mut queue, 350);

        assert_eq!(queue.len(), 1);

        let sr = match queue.pop_front().unwrap() {
            RtcpFb::ReceiverReport(v) => v,
            _ => unreachable!(),
        };

        assert_eq!(sr.reports.len(), 4);
        let mut iter = sr.reports.iter();
        assert_eq!(iter.next().unwrap(), &report(1));
        assert_eq!(iter.next().unwrap(), &report(2));
        assert_eq!(iter.next().unwrap(), &report(3));
        assert_eq!(iter.next().unwrap(), &report(4));
    }

    #[test]
    fn roundtrip_sr_rr() {
        let now = MediaTime::now();
        let mut feedback = VecDeque::new();
        feedback.push_back(sr(1, now));
        feedback.push_back(rr(3));
        feedback.push_back(rr(4));
        feedback.push_back(rr(5));

        let mut buf = vec![0_u8; 1360];
        let n = RtcpFb::write_packet(&mut feedback, &mut buf, 16);
        buf.truncate(n);

        let parsed = RtcpFb::read_packet(&buf).unwrap();

        let mut compare = VecDeque::new();
        compare.push_back(sr(1, now));
        compare.push_back(rr(3));
        compare.push_back(rr(4));
        compare.push_back(rr(5));
        RtcpFb::pack(&mut compare, 1400);

        assert_eq!(parsed, compare);
    }

    fn sr(ssrc: u32, ntp_time: MediaTime) -> RtcpFb {
        RtcpFb::SenderReport(SenderReport {
            sender_info: SenderInfo {
                ssrc: ssrc.into(),
                ntp_time,
                rtp_time: 4,
                sender_packet_count: 5,
                sender_octet_count: 6,
            },
            reports: report(2).into(),
        })
    }

    fn rr(ssrc: u32) -> RtcpFb {
        RtcpFb::ReceiverReport(ReceiverReport {
            reports: report(ssrc).into(),
        })
    }

    fn report(ssrc: u32) -> ReceptionReport {
        ReceptionReport {
            ssrc: ssrc.into(),
            fraction_lost: 3,
            packets_lost: 1234,
            max_seq: 4000,
            jitter: 5,
            last_sr_time: 12,
            last_sr_delay: 1,
        }
    }

    // fn sdes(ssrc: u32) -> RtcpFb {
    //     RtcpFb::Sdes(Sdes {
    //         ssrc: ssrc.into(),
    //         values: vec![
    //             (SdesType::NAME, "Martin".into()),
    //             (SdesType::TOOL, "str0m".into()),
    //             (SdesType::NOTE, "Writing things right here".into()),
    //         ],
    //     })
    // }

    // fn nack(ssrc: u32, pid: u16) -> RtcpFb {
    //     RtcpFb::Nack(Nack {
    //         ssrc: ssrc.into(),
    //         pid,
    //         blp: 0b1010_0101,
    //     })
    // }

    // fn gb(ssrc: u32) -> RtcpFb {
    //     RtcpFb::Goodbye(ssrc.into())
    // }
}
