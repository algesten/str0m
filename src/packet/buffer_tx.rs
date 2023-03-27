use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp::{ExtensionValues, MediaTime, Rid, SeqNo, Ssrc};

use super::MediaKind;
use super::{CodecPacketizer, PacketError, Packetizer, QueueSnapshot};

pub struct Packetized {
    pub data: Vec<u8>,
    pub first: bool,
    pub last: bool,

    pub meta: PacketizedMeta,

    /// Set when packet is first sent. This is so we can resend.
    pub seq_no: Option<SeqNo>,
    /// Whether this packetized is counted towards the TotalQueue
    pub count_as_unsent: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketizedMeta {
    pub rtp_time: MediaTime,
    pub ssrc: Ssrc,
    pub rid: Option<Rid>,
    pub ext_vals: ExtensionValues,
    #[doc(hidden)]
    pub queued_at: Instant,
}

#[derive(Debug)]
pub struct PacketizingBuffer {
    pack: CodecPacketizer,
    queue: VecDeque<Packetized>,

    emit_next: usize,
    last_emit: Option<Instant>,
    max_retain: usize,

    total: TotalQueue,
}

impl PacketizingBuffer {
    pub fn new(pack: CodecPacketizer, max_retain: usize) -> Self {
        PacketizingBuffer {
            pack,
            queue: VecDeque::new(),

            emit_next: 0,
            last_emit: None,
            max_retain,

            total: TotalQueue::default(),
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
        let now = meta.queued_at;
        self.total.move_time_forward(now);

        assert!(len <= self.max_retain, "Must retain at least chunked count");

        for (idx, data) in chunks.into_iter().enumerate() {
            let first = idx == 0;
            let last = idx == len - 1;

            // The queue_time for a new entry is ZERO since we expect packets to be
            // enqueued straight away. If we get rid of the now: Instant in media
            // writing to only rely on handle_timeout, this might not hold true.
            self.total.increase(now, Duration::ZERO, data.len());

            let rtp = Packetized {
                first,
                last,
                data,

                meta,

                seq_no: None,
                count_as_unsent: true,
            };

            self.queue.push_back(rtp);
        }

        // Scale back retained count to max_retain
        while self.queue.len() > self.max_retain {
            let p = self.queue.pop_front();
            if let Some(p) = p {
                if p.count_as_unsent {
                    let queue_time = now - p.meta.queued_at;
                    self.total.decrease(p.data.len(), queue_time);
                }
            }
            self.emit_next -= 1;
        }

        Ok(())
    }

    pub fn poll_next(&mut self, now: Instant) -> Option<&mut Packetized> {
        self.total.move_time_forward(now);
        let next = self.queue.get_mut(self.emit_next)?;
        if next.count_as_unsent {
            next.count_as_unsent = false;
            let queue_time = now - next.meta.queued_at;
            self.total.decrease(next.data.len(), queue_time);
        }
        self.emit_next += 1;
        self.last_emit = Some(now);
        Some(next)
    }

    pub fn get(&self, seq_no: SeqNo) -> Option<&Packetized> {
        self.queue.iter().find(|r| r.seq_no == Some(seq_no))
    }

    // Used when we get a resend to account for resends in the TotalQueue.
    pub fn mark_as_unaccounted(&mut self, now: Instant, seq_no: SeqNo) {
        self.total.move_time_forward(now);
        let Some(p) = self.queue.iter_mut().find(|r| r.seq_no == Some(seq_no)) else {
            return;
        };

        if !p.count_as_unsent {
            p.count_as_unsent = true;
            let queue_time = now - p.meta.queued_at;
            self.total.increase(now, queue_time, p.data.len());
        }
    }

    // Used when we handle a resend to update TotalQueue.
    pub fn get_and_unmark_as_accounted(
        &mut self,
        now: Instant,
        seq_no: SeqNo,
    ) -> Option<&Packetized> {
        self.total.move_time_forward(now);
        let p = self.queue.iter_mut().find(|r| r.seq_no == Some(seq_no))?;

        if p.count_as_unsent {
            p.count_as_unsent = false;
            let queue_time = now - p.meta.queued_at;
            self.total.decrease(p.data.len(), queue_time);
        }

        Some(p)
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

    pub fn queue_snapshot(&mut self, now: Instant) -> QueueSnapshot {
        self.total.move_time_forward(now);

        QueueSnapshot {
            created_at: now,
            size: self.total.unsent_size,
            packet_count: self.total.unsent_count as u32,
            total_queue_time_origin: self.total.queue_time,
            last_emitted: self.last_emit,
            first_unsent: self.queue.get(self.emit_next).map(|p| p.meta.queued_at),
        }
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

// Total queue time in buffer. This lovely drawing explains how to add more time.
//
// -time--------------------------------------------------------->
//
// +--------------+
// |              |
// +--------------+
//      +---------+                          Already
//      |         |                           queued
//      +---------+                         durations
//          +-----+
//          |     |
//          +-----+
//                       +-+
//                       | |         <-----  Add next
//                       +-+                  packet
//
//
//
// +--------------+--------+
// |              |@@@@@@@@|
// +--------------+--------+
//      +---------+--------+                 The @ is
//      |         |@@@@@@@@|                  what's
//      +---------+--------+                  added
//          +-----+--------+
//          |     |@@@@@@@@|
//          +-----+--------+
//                       +-+
//                       |@|
//                       +-+
#[derive(Debug, Default)]
struct TotalQueue {
    /// Number of unsent packets.
    unsent_count: usize,
    /// The data size (bytes) of the unsent packets.
    unsent_size: usize,
    /// When we last added some value to `queue_time`.
    last: Option<Instant>,
    /// The total queue time of all the unsent packets.
    queue_time: Duration,
}

impl TotalQueue {
    fn move_time_forward(&mut self, now: Instant) {
        if let Some(last) = self.last {
            assert!(self.unsent_count > 0);
            assert!(self.unsent_size > 0);
            let from_last = now - last;
            self.queue_time += from_last * (self.unsent_count as u32);
            self.last = Some(now);
        } else {
            assert!(self.unsent_count == 0);
            assert!(self.unsent_size == 0);
            assert!(self.queue_time == Duration::ZERO);
        }
    }

    fn increase(&mut self, now: Instant, queue_time: Duration, size: usize) {
        self.unsent_count += 1;
        self.unsent_size += size;
        self.queue_time += queue_time;
        self.last = Some(now);
    }

    fn decrease(&mut self, size: usize, queue_time: Duration) {
        self.unsent_count -= 1;
        self.unsent_size -= size;
        self.queue_time -= queue_time;
        if self.unsent_count == 0 {
            assert!(self.unsent_size == 0);
            assert!(self.queue_time == Duration::ZERO);
            self.last = None;
        }
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
