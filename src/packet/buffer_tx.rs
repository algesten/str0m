use std::collections::VecDeque;
use std::fmt;
use std::time::Instant;

use crate::rtp::{ExtensionValues, MediaTime, Rid, SeqNo, Ssrc};

use super::pacer::PacketKind;
use super::{CodecPacketizer, PacketError, Packetizer, QueueState};

pub struct Packetized {
    pub data: Vec<u8>,
    pub first: bool,
    pub last: bool,

    pub meta: PacketizedMeta,

    /// Set when packet is first sent. This is so we can resend.
    pub seq_no: Option<SeqNo>,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketizedMeta {
    pub rtp_time: MediaTime,
    pub ssrc: Ssrc,
    pub rid: Option<Rid>,
    pub ext_vals: ExtensionValues,
    pub queued_at: Instant,
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
    pub fn new(pack: CodecPacketizer, max_retain: usize) -> Self {
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

            let rtp = Packetized {
                first,
                last,
                data,

                meta,

                seq_no: None,
            };

            self.queue.push_back(rtp);
        }

        // Scale back retained count to max_retain
        while self.queue.len() > self.max_retain {
            self.queue.pop_front();
            self.emit_next = self.emit_next.saturating_sub(1);
        }

        Ok(())
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

    pub fn queue_state(&self, now: Instant) -> QueueState {
        let kind = if self.is_audio() {
            PacketKind::Audio
        } else {
            PacketKind::Video
        };

        let mut state = self
            .queued_packets()
            .fold(QueueState::new(kind), |mut state, packet| {
                state.packet_count += 1;
                state.total_queue_time += now.saturating_duration_since(packet.meta.queued_at);
                state.size += packet.data.len().into();

                state
            });

        state.update_last_send_time(self.last_emit);
        state.update_leading_queue_time(self.leading_queue_time());

        state
    }

    /// The size of the resend history in this buffer.
    pub fn history_size(&self) -> usize {
        self.emit_next
    }

    pub fn leading_queue_time(&self) -> Option<Instant> {
        self.queued_packets().next().map(|p| p.meta.queued_at)
    }

    fn is_audio(&self) -> bool {
        self.pack.is_audio()
    }

    /// An iterator over all packets that are queued, but have not yet been sent.
    fn queued_packets(&self) -> impl Iterator<Item = &Packetized> {
        // seq_no is some as long as packet has not been sent
        self.queue.iter().skip_while(|p| p.seq_no.is_some())
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
            .field("last", &self.last)
            .field("ssrc", &self.meta.ssrc)
            .field("seq_no", &self.seq_no)
            .finish()
    }
}
