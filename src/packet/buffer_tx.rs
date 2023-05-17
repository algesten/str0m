use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp::{ExtensionValues, MediaTime, Rid, RtpHeader, SeqNo, Ssrc};

use super::{CodecPacketizer, PacketError, Packetizer, QueueSnapshot};
use super::{MediaKind, QueuePriority};

pub struct Packetized {
    pub data: Vec<u8>,
    pub first: bool,
    pub marker: bool,
    pub meta: PacketizedMeta,
    pub queued_at: Instant,

    /// Set when packet is first sent. This is so we can resend.
    pub seq_no: Option<SeqNo>,
    /// Whether this packetized is counted towards the TotalQueue
    pub count_as_unsent: bool,

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

    total: TotalQueue,
}

impl PacketizingBuffer {
    pub(crate) fn new(pack: CodecPacketizer, max_retain: usize) -> Self {
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
        now: Instant,
        data: &[u8],
        meta: PacketizedMeta,
        mtu: usize,
    ) -> Result<(), PacketError> {
        let chunks = self.pack.packetize(mtu, data)?;
        let len = chunks.len();
        self.total.move_time_forward(now);

        assert!(len <= self.max_retain, "Must retain at least chunked count");

        for (idx, data) in chunks.into_iter().enumerate() {
            let first = idx == 0;
            let last = idx == len - 1;

            let previous_data = self.queue.back().map(|p| p.data.as_slice());
            let marker = self.pack.is_marker(data.as_slice(), previous_data, last);

            self.total.increase(now, Duration::ZERO, data.len());

            let rtp = Packetized {
                first,
                marker,
                data,
                meta,
                queued_at: now,

                seq_no: None,
                count_as_unsent: true,

                rtp_mode_header: None,
            };

            self.queue.push_back(rtp);
        }

        self.size_down_to_retained(now);

        Ok(())
    }

    pub fn push_rtp_packet(
        &mut self,
        now: Instant,
        data: Vec<u8>,
        meta: PacketizedMeta,
        rtp_header: RtpHeader,
    ) {
        self.total.move_time_forward(now);

        self.total.increase(now, Duration::ZERO, data.len());

        let rtp = Packetized {
            first: true,
            marker: rtp_header.marker,
            data,
            meta,
            queued_at: now,

            // don't set seq_no yet since it's used to determine if packet has been sent or not.
            seq_no: None,
            count_as_unsent: true,

            rtp_mode_header: Some(rtp_header),
        };

        self.queue.push_back(rtp);

        self.size_down_to_retained(now);
    }

    /// Scale back retained count to max_retain
    fn size_down_to_retained(&mut self, now: Instant) {
        while self.queue.len() > self.max_retain {
            let p = self.queue.pop_front();
            if let Some(p) = p {
                if p.count_as_unsent {
                    let queue_time = now - p.queued_at;
                    self.total.decrease(p.data.len(), queue_time);
                }
            }
            if self.emit_next == 0 {
                // This probably means the user is doing a lot of MediaWriter::write()
                // without interspersing it with Rtc::poll_output() or maybe doing
                // writes before the Connected event.
                panic!("Resize down PacketizingBuffer when emit_next is at 0");
            }
            self.emit_next -= 1;
        }
    }

    pub fn poll_next(&mut self, now: Instant) -> Option<&mut Packetized> {
        self.total.move_time_forward(now);
        let next = self.queue.get_mut(self.emit_next)?;
        if next.count_as_unsent {
            next.count_as_unsent = false;
            let queue_time = now - next.queued_at;
            self.total.decrease(next.data.len(), queue_time);
        }
        self.emit_next += 1;
        self.last_emit = Some(now);
        Some(next)
    }

    pub fn get(&self, seq_no: SeqNo) -> Option<&Packetized> {
        // rev because we almost always get packets that are recent (for resends
        // and spurious padding). Worst case is still `O(n)` here but by
        // searching backwards we improve actual performance.
        self.queue.iter().rev().find(|r| r.seq_no == Some(seq_no))
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
            first_unsent: self.queue.get(self.emit_next).map(|p| p.queued_at),
            priority: if self.total.unsent_count > 0 {
                QueuePriority::Media
            } else {
                QueuePriority::Empty
            },
        }
    }

    /// The size of the resend history in this buffer.
    pub fn history_size(&self) -> usize {
        self.emit_next
    }

    /// Find a historic packet that is smaller than the given max_size.
    pub fn historic_packet_smaller_than(&self, max_size: usize) -> Option<&Packetized> {
        return self
            .queue
            .iter()
            .rev()
            .filter(|p| p.seq_no.is_some() && p.data.len() < max_size)
            .max_by_key(|p| p.data.len());
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
            self.queue_time = Duration::ZERO;
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
            .field("last", &self.marker)
            .field("ssrc", &self.meta.ssrc)
            .field("seq_no", &self.seq_no)
            .finish()
    }
}
