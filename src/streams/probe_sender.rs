//! SSRC 0 BWE probe sender.
//!
//! Generates padding-only RTP packets on SSRC 0 for bandwidth probing before
//! any real video media is sent.

use std::time::{Duration, Instant};

use crate::io::DATAGRAM_MAX_PACKET_SIZE;
use crate::media::MID_PROBE;
use crate::packet::{QueuePriority, QueueSnapshot, QueueState};
use crate::rtp_::{ExtensionMap, ExtensionValues, MidRid, Pt, RtpHeader, SeqNo, Ssrc};
use crate::rtp_::{MAX_BLANK_PADDING_PAYLOAD_SIZE, SRTP_BLOCK_SIZE};
use crate::session::PacketReceipt;

/// Generates SSRC 0 BWE probe packets before video media starts.
pub(crate) struct ProbeSender {
    /// RTP sequence number counter (separate from real streams)
    seq_no: SeqNo,

    /// Pending padding bytes to send (set by pacer)
    padding: usize,

    /// PT to use - should be an RTX PT from negotiated video
    pt: Pt,
}

impl ProbeSender {
    /// Create a new probe sender with the given RTX payload type.
    pub fn new(pt: Pt) -> Self {
        Self {
            seq_no: SeqNo::from(fastrand::u16(..) as u64),
            padding: 0,
            pt,
        }
    }

    /// Create a QueueState for the probe sender.
    ///
    /// Reports pending padding as queued packets so pacer's `poll_queue()` returns `MID_PROBE`.
    pub fn probe_queue_state(&self, now: Instant) -> QueueState {
        let (packet_count, priority) = if self.has_padding() {
            (1, QueuePriority::Padding)
        } else {
            (0, QueuePriority::Empty)
        };

        QueueState {
            midrid: MidRid(MID_PROBE, None),
            unpaced: false,        // Probes should be paced
            use_for_padding: true, // This is what makes pacer consider it for padding
            snapshot: QueueSnapshot {
                created_at: now,
                size: 0,
                packet_count,
                total_queue_time_origin: Duration::ZERO,
                last_emitted: Some(now), // Pretend recently active
                first_unsent: if self.has_padding() { Some(now) } else { None },
                priority,
            },
        }
    }

    /// Check if we have padding to send.
    pub fn has_padding(&self) -> bool {
        self.padding > 0
    }

    /// Request padding (called when pacer wants probes).
    pub fn generate_padding(&mut self, amount: usize) {
        self.padding = self.padding.saturating_add(amount);
    }

    /// Generate probe packet, write to buffer, return receipt.
    ///
    /// Returns `None` if no padding is pending.
    pub fn poll_packet(
        &mut self,
        twcc: &mut SeqNo,
        exts: &ExtensionMap,
        buf: &mut Vec<u8>,
    ) -> Option<PacketReceipt> {
        if self.padding == 0 {
            return None;
        }

        let twcc_seq = twcc.inc();
        let seq_no = self.seq_no.inc();

        // Consume padding (clamp to reasonable size)
        let payload_size = self
            .padding
            .clamp(SRTP_BLOCK_SIZE, MAX_BLANK_PADDING_PAYLOAD_SIZE);
        self.padding = self.padding.saturating_sub(payload_size);

        let mut header = RtpHeader {
            version: 2,
            has_padding: true,
            has_extension: true,
            marker: false,
            payload_type: self.pt,
            sequence_number: *seq_no as u16,
            timestamp: 0, // Probes don't need meaningful timestamp
            ssrc: Ssrc::from(0u32),
            ext_vals: ExtensionValues {
                transport_cc: Some(*twcc_seq as u16),
                ..Default::default()
            },
            header_len: 0, // Will be set below
        };

        // Write to buffer (must resize before write_to)
        buf.resize(DATAGRAM_MAX_PACKET_SIZE, 0);
        let header_len = header.write_to(buf, exts);
        header.header_len = header_len;
        let total_len = header_len + payload_size;
        buf.truncate(total_len);
        buf[total_len - 1] = payload_size as u8;

        let receipt = PacketReceipt {
            header,
            seq_no,
            is_padding: true,
            payload_size,
            twcc_seq: Some(twcc_seq),
        };

        Some(receipt)
    }
}
