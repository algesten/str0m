use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::packet::{QueuePriority, QueueSnapshot};

use super::RtpPacket;

#[derive(Debug)]
pub(crate) struct SendQueue {
    queue: VecDeque<RtpPacket>,
    total: TotalQueue,
    last_emitted: Option<Instant>,
}

impl SendQueue {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            total: TotalQueue::default(),
            last_emitted: None,
        }
    }

    pub fn push(&mut self, packet: RtpPacket) {
        self.queue.push_back(packet);
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        for pkt in self.queue.iter_mut().rev() {
            if pkt.timestamp < now {
                // all enqueued packets are timestamped.
                break;
            } else {
                pkt.timestamp = now;
                self.total.increase(now, pkt.payload.len());
            }
        }
    }

    pub fn pop(&mut self, now: Instant) -> Option<RtpPacket> {
        if let Some(packet) = self.queue.pop_front() {
            // If the popped packet has a timestamp in the future, we have not counted it
            // towards the queue total (see handle_timeout).
            if now >= packet.timestamp {
                let queue_time = now - packet.timestamp;
                self.total.decrease(now, packet.payload.len(), queue_time);
            }
            self.last_emitted = Some(now);
            Some(packet)
        } else {
            None
        }
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn last(&self) -> Option<&RtpPacket> {
        self.queue.back()
    }

    pub(crate) fn snapshot(&mut self, now: Instant) -> QueueSnapshot {
        self.total.move_time_forward(now);

        QueueSnapshot {
            created_at: now,
            size: self.total.unsent_size,
            packet_count: self.total.unsent_count as u32,
            total_queue_time_origin: self.total.queue_time,
            last_emitted: self.last_emitted,
            first_unsent: self.queue.front().map(|p| p.timestamp),
            priority: if self.total.unsent_count > 0 {
                QueuePriority::Media
            } else {
                QueuePriority::Empty
            },
        }
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
    // /// When we last added some value to `queue_time`.
    // last: Option<Instant>,
    /// The total queue time of all the unsent packets.
    queue_time: Duration,
    // Timestamp of the last added packet.
    last: Option<Instant>,
}

impl TotalQueue {
    fn move_time_forward(&mut self, now: Instant) {
        if let Some(last) = self.last {
            assert!(self.unsent_count > 0);
            let from_last = now - last;
            self.queue_time += from_last * (self.unsent_count as u32);
            self.last = Some(now);
        } else {
            assert!(self.unsent_count == 0);
            assert!(self.unsent_size == 0);
            assert!(self.queue_time == Duration::ZERO);
        }
    }

    fn increase(&mut self, now: Instant, size: usize) {
        self.move_time_forward(now);
        self.unsent_count += 1;
        self.unsent_size += size;
        self.last = Some(now);
    }

    fn decrease(&mut self, now: Instant, size: usize, queue_time: Duration) {
        self.move_time_forward(now);

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
