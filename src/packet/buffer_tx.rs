use std::collections::HashMap;
use std::collections::{BTreeMap, VecDeque};

use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp::{ExtensionValues, MediaTime, Pt, Rid, RtpHeader, SeqNo, Ssrc};

use super::{CodecPacketizer, PacketError, Packetizer, QueueSnapshot};
use super::{MediaKind, QueuePriority};

pub struct Packetized {
    pub data: Vec<u8>,
    pub first: bool,
    pub marker: bool,
    pub meta: PacketizedMeta,
    pub queued_at: Instant,
    /// If we are in rtp_mode, this is the original incoming header.
    pub rtp_mode_header: Option<RtpHeader>,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketizedMeta {
    pub pt: Pt,
    pub rtp_time: MediaTime,
    pub ssrc: Ssrc,
    pub rid: Option<Rid>,
    pub ext_vals: ExtensionValues,
}

#[derive(Debug)]
pub struct PacketizingBuffer {
    pack: CodecPacketizer,
    queue: VecDeque<Packetized>,

    last_emit: Option<Instant>,
    max_packet_count: usize,

    total: TotalQueue,

    // Set when we first discover the SSRC
    ssrc: Option<Ssrc>,
}

const SIZE_BUCKET: usize = 25;

impl PacketizingBuffer {
    pub(crate) fn new(pack: CodecPacketizer, max_packet_count: usize) -> Self {
        PacketizingBuffer {
            pack,
            queue: VecDeque::new(),

            last_emit: None,
            max_packet_count,

            total: TotalQueue::default(),
            ssrc: None,
        }
    }

    pub fn push_sample(
        &mut self,
        now: Instant,
        data: &[u8],
        meta: PacketizedMeta,
        mtu: usize,
    ) -> Result<bool, PacketError> {
        let chunks = self.pack.packetize(mtu, data)?;
        let len = chunks.len();

        assert!(
            len <= self.max_packet_count,
            "Data larger than send buffer {} > {}",
            data.len(),
            self.max_packet_count
        );

        for (idx, data) in chunks.into_iter().enumerate() {
            let first = idx == 0;
            let last = idx == len - 1;

            let previous_data = self.queue.back().map(|p| p.data.as_slice());
            let marker = self.pack.is_marker(data.as_slice(), previous_data, last);

            let overflow = self.push_packet(
                Packetized {
                    first,
                    marker,
                    data,
                    meta,
                    queued_at: now,

                    rtp_mode_header: None,
                },
                now,
            );

            if overflow {
                return Ok(overflow);
            }
        }
        Ok(false)
    }

    pub fn push_rtp_packet(
        &mut self,
        now: Instant,
        data: Vec<u8>,
        meta: PacketizedMeta,
        rtp_header: RtpHeader,
    ) -> bool {
        self.push_packet(
            Packetized {
                first: true,
                marker: rtp_header.marker,
                data,
                meta,
                queued_at: now,

                rtp_mode_header: Some(rtp_header),
            },
            now,
        )
    }

    fn push_packet(&mut self, pkt: Packetized, now: Instant) -> bool {
        self.total.move_time_forward(now);

        if self.ssrc.is_none() {
            self.ssrc = Some(pkt.meta.ssrc);
        }

        self.total.increase(now, pkt.data.len());

        self.queue.push_back(pkt);

        let overflow = self.queue.len() > self.max_packet_count;
        if overflow {
            self.overflow_reset(now);
        }
        overflow
    }

    fn overflow_reset(&mut self, now: Instant) {
        let last_pkt = self.queue.pop_back();
        self.queue = VecDeque::new();
        self.total = TotalQueue::default();
        if let Some(first_pkt) = last_pkt {
            self.push_packet(first_pkt, now);
        }

        warn!("Send buffer overflow; increase send buffer size");
    }

    pub fn pop_next(&mut self, now: Instant) -> Option<Packetized> {
        self.total.move_time_forward(now);

        let next = self.queue.pop_front()?;

        let queue_time = now - next.queued_at;
        self.total.decrease(next.data.len(), queue_time);

        self.last_emit = Some(now);

        Some(next)
    }

    pub fn queue_snapshot(&mut self, now: Instant) -> QueueSnapshot {
        self.total.move_time_forward(now);

        QueueSnapshot {
            created_at: now,
            size: self.total.unsent_size,
            packet_count: self.total.unsent_count as u32,
            total_queue_time_origin: self.total.queue_time,
            last_emitted: self.last_emit,
            first_unsent: self.queue.front().map(|p| p.queued_at),
            priority: if self.total.unsent_count > 0 {
                QueuePriority::Media
            } else {
                QueuePriority::Empty
            },
        }
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc.expect("Send buffer to have an SSRC")
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
            if last != now {
                let from_last = now - last;
                self.queue_time += from_last * (self.unsent_count as u32);
                self.last = Some(now);
            }
        } else {
            assert!(self.unsent_count == 0);
            assert!(self.unsent_size == 0);
            assert!(self.queue_time == Duration::ZERO);
        }
    }

    fn increase(&mut self, now: Instant, size: usize) {
        self.unsent_count += 1;
        self.unsent_size += size;
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
            .finish()
    }
}
