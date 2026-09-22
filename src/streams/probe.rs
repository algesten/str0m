use std::time::Instant;

use crate::pacer::{QueuePriority, QueueSnapshot};
use crate::rtp_::{ExtensionMap, ExtensionValues, MAX_BLANK_PADDING_PAYLOAD_SIZE, Mid, Pt};
use crate::rtp_::{RtpHeader, SRTP_BLOCK_SIZE};
use crate::session::PacketReceipt;

/// Padding-only SSRC 0, with its own extended SRTP sequence number.
#[derive(Default)]
pub(crate) struct ProbeTx {
    seq_no: u64,
    padding: usize,
    last_sent: Option<Instant>,
}

impl ProbeTx {
    pub fn generate_padding(&mut self, bytes: usize) {
        self.padding = bytes;
    }

    pub fn clear(&mut self) {
        self.padding = 0;
    }

    pub fn queue_state(&self, now: Instant) -> QueueSnapshot {
        QueueSnapshot {
            created_at: now,
            byte_size: self.padding,
            packet_count: self.padding.div_ceil(MAX_BLANK_PADDING_PAYLOAD_SIZE) as u32,
            first_unsent: (self.padding > 0).then_some(now),
            last_emitted: self.last_sent,
            priority: if self.padding > 0 {
                QueuePriority::Padding
            } else {
                QueuePriority::Empty
            },
            ..Default::default()
        }
    }

    pub fn poll_packet(
        &mut self,
        now: Instant,
        mid: Mid,
        pt: Pt,
        exts: &ExtensionMap,
        twcc: &mut u64,
        buf: &mut Vec<u8>,
    ) -> Option<PacketReceipt> {
        if self.padding == 0 {
            return None;
        }
        let mut header = RtpHeader {
            has_padding: true,
            payload_type: pt,
            sequence_number: self.seq_no as u16,
            ssrc: 0.into(),
            ext_vals: ExtensionValues {
                mid: Some(mid),
                transport_cc: Some(*twcc as u16),
                ..Default::default()
            },
            ..Default::default()
        };
        buf.resize(2000, 0);
        header.header_len = header.write_to(buf, exts);
        // Like RTPSender::GeneratePadding, split a probe burst into bounded RTP
        // padding packets. Charge the actual rounded size to the pacer and TWCC.
        let size = RtpHeader::create_padding_packet(
            buf,
            header.header_len,
            self.padding.min(MAX_BLANK_PADDING_PAYLOAD_SIZE) as u8,
            SRTP_BLOCK_SIZE,
        );
        buf.truncate(header.header_len + size);
        self.padding = self.padding.saturating_sub(size);
        self.last_sent = Some(now);
        let seq_no = self.seq_no.into();
        self.seq_no += 1;
        *twcc += 1;
        Some(PacketReceipt {
            header,
            seq_no,
            is_padding: true,
            payload_size: size,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn padding_accounting_and_sequence_rollover() {
        let now = Instant::now();
        let mut sender = ProbeTx {
            seq_no: 65_535,
            ..Default::default()
        };
        let mut twcc = 131_071;
        let mut buf = vec![];
        let exts = ExtensionMap::standard();
        sender.generate_padding(241);
        let first = sender
            .poll_packet(now, "aud".into(), 111.into(), &exts, &mut twcc, &mut buf)
            .unwrap();
        assert_eq!(first.payload_size, 240);
        assert_eq!(*first.seq_no, 65_535);
        let second = sender
            .poll_packet(now, "aud".into(), 111.into(), &exts, &mut twcc, &mut buf)
            .unwrap();
        assert_eq!(*second.seq_no, 65_536);
        assert_eq!(second.header.sequence_number, 0);
        assert_eq!(second.header.ext_vals.transport_cc, Some(0));
        assert_eq!(second.payload_size, SRTP_BLOCK_SIZE);
        assert_eq!(buf.len(), second.header.header_len + second.payload_size);
        assert!(
            RtpHeader::unpad_payload(&buf[second.header.header_len..])
                .unwrap()
                .is_empty()
        );
        assert_eq!(sender.queue_state(now).packet_count, 0);
        assert_eq!(twcc, 131_073);
    }
}
