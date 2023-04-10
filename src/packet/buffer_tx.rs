use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp::{ExtensionValues, MediaTime, Rid, RtpHeader, SeqNo, Ssrc};

use super::MediaKind;
use super::{CodecPacketizer, PacketError, Packetizer};

pub struct Packetized {
    pub data: Vec<u8>,
    pub first: bool,
    pub marker: bool,
    pub meta: PacketizedMeta,

    /// Set when packet is first sent. This is so we can resend.
    pub seq_no: Option<SeqNo>,

    /// If we are in rtp_mode, this is the original incoming header.
    pub rtp_mode_header: Option<RtpHeader>,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketizedMeta {
    pub rtp_time: MediaTime,
    pub ssrc: Ssrc,
    pub rid: Option<Rid>,
    pub ext_vals: ExtensionValues,
}

#[derive(Debug)]
pub struct PacketizingBuffer {
    pack: CodecPacketizer,
    queue: VecDeque<Packetized>,

    emit_next: usize,
    last_emit: Option<Instant>,
    max_retain: usize,
}

impl PacketizingBuffer {
    pub(crate) fn new(pack: CodecPacketizer, max_retain: usize) -> Self {
        PacketizingBuffer {
            pack,
            queue: VecDeque::new(),

            emit_next: 0,
            last_emit: None,
            max_retain,
        }
    }

    pub fn push_sample(
        &mut self,
        data: &[u8],
        meta: PacketizedMeta,
        mtu: usize,
    ) -> Result<(), PacketError> {
        let chunks = self.pack.packetize(mtu, data)?;
        let len = chunks.len();

        assert!(len <= self.max_retain, "Must retain at least chunked count");

        for (idx, data) in chunks.into_iter().enumerate() {
            let first = idx == 0;
            let last = idx == len - 1;

            let previous_data = self.queue.back().map(|p| p.data.as_slice());
            let marker = self.pack.is_marker(data.as_slice(), previous_data, last);

            let rtp = Packetized {
                first,
                marker,
                data,
                meta,

                seq_no: None,

                rtp_mode_header: None,
            };

            self.queue.push_back(rtp);
        }

        Ok(())
    }

    pub fn push_rtp_packet(&mut self, data: Vec<u8>, meta: PacketizedMeta, rtp_header: RtpHeader) {
        let rtp = Packetized {
            first: true,
            marker: rtp_header.marker,
            data,
            meta,

            // don't set seq_no yet since it's used to determine if packet has been sent or not.
            seq_no: None,

            rtp_mode_header: Some(rtp_header),
        };

        self.queue.push_back(rtp);
    }

    /// Scale back retained count to max_retain
    fn size_down_to_retained(&mut self, now: Instant) {
        while self.queue.len() > self.max_retain {
            self.queue.pop_front();
            self.emit_next -= 1;
        }
    }

    pub fn poll_next(&mut self, now: Instant) -> Option<&mut Packetized> {
        let next = self.queue.get_mut(self.emit_next)?;
        self.emit_next += 1;
        self.last_emit = Some(now);
        Some(next)
    }

    pub fn get(&self, seq_no: SeqNo) -> Option<&Packetized> {
        self.queue.iter().find(|r| r.seq_no == Some(seq_no))
    }

    pub fn has_ssrc(&self, ssrc: Ssrc) -> bool {
        self.queue
            .front()
            .map(|p| p.meta.ssrc == ssrc)
            .unwrap_or(false)
    }

    pub fn first_seq_no(&self) -> Option<SeqNo> {
        self.queue.front().and_then(|p| p.seq_no)
    }

    pub fn free(&self) -> usize {
        self.max_retain - self.queue.len() + self.emit_next
    }

    /// The size of the resend history in this buffer.
    pub fn history_size(&self) -> usize {
        self.emit_next
    }

    /// Find a historic packet that is smaller than the given max_size.
    pub fn historic_packet_smaller_than(&self, max_size: usize) -> Option<&Packetized> {
        for packet in self.queue.iter().rev() {
            // as long as seq_no is none, the packet has not been sent.
            if packet.seq_no.is_none() {
                continue;
            }

            if packet.data.len() < max_size {
                return Some(packet);
            }
        }

        None
    }
}

impl fmt::Debug for Packetized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packetized")
            .field("rtp_time", &self.meta.rtp_time)
            .field("len", &self.data.len())
            .field("first", &self.first)
            .field("last", &self.marker)
            .field("ssrc", &self.meta.ssrc)
            .field("seq_no", &self.seq_no)
            .finish()
    }
}
