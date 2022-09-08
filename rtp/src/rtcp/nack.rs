use crate::{
    FeedbackMessageType, ReportList, RtcpHeader, RtcpPacket, RtcpType, Ssrc, TransportType,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nack {
    pub ssrc: Ssrc,
    pub reports: ReportList<NackPair>,
}

#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct NackPair {
    pub packet_id: u16,
    pub lost_packets: u16,
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
        2 + self.reports.len()
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        (&mut buf[0..4]).copy_from_slice(&0_u16.to_be_bytes());
        (&mut buf[4..8]).copy_from_slice(&self.ssrc.to_be_bytes());
        let mut buf = &mut buf[8..];
        for r in &self.reports {
            (&mut buf[0..2]).copy_from_slice(&r.packet_id.to_be_bytes());
            (&mut buf[2..4]).copy_from_slice(&r.lost_packets.to_be_bytes());
            buf = &mut buf[4..];
        }
        todo!()
    }
}

impl<'a> TryFrom<&'a [u8]> for Nack {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 12 {
            return Err("Nack less than 12 bytes");
        }

        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]).into();

        let mut reports = ReportList::new();

        let mut buf = &buf[8..];
        let count = buf.len() / 4;
        let max = count.min(31);

        for _ in 0..max {
            let packet_id = u16::from_be_bytes([buf[0], buf[1]]);
            let lost_packets = u16::from_be_bytes([buf[2], buf[3]]);
            reports.push(NackPair {
                packet_id,
                lost_packets,
            });
            buf = &buf[4..];
        }

        Ok(Nack { ssrc, reports })
    }
}
