use std::collections::HashMap;
use std::collections::{BTreeMap, VecDeque};

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
    queue: RingBuf<Packetized>,
    by_seq: HashMap<SeqNo, Ident>,
    by_size: BTreeMap<usize, Ident>,

    emit_next: Ident,
    last_emit: Option<Instant>,
    max_retain: usize,

    total: TotalQueue,
}

const SIZE_BUCKET: usize = 25;

#[derive(Debug)]
struct RingBuf<T> {
    buffer: Vec<Option<T>>,
    len: usize,
    // This is an u64 since it is ever growing and used as an identifier.
    next: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Ident(u64);

impl Ident {
    pub fn increase(&self) -> Ident {
        Ident(self.0 + 1)
    }
}

impl<T> RingBuf<T> {
    pub fn new(len: usize) -> Self {
        // We don't want to require T: Clone.
        let mut buffer = Vec::with_capacity(len);
        for _ in 0..len {
            buffer.push(None);
        }

        Self {
            buffer,
            len,
            next: 0,
        }
    }

    pub fn push(&mut self, t: T) -> (Ident, Option<T>) {
        let idx = (self.next % self.len as u64) as usize;

        let prev = self.buffer[idx].take();
        self.buffer[idx] = Some(t);

        let ident = Ident(self.next);
        self.next += 1;

        (ident, prev)
    }

    fn index_in_scope(&self, i: Ident) -> Option<usize> {
        // [ a, b, c, d, e ]
        //         ^
        //         c
        //   ^           ^
        //   i           i
        let l = self.len as u64;

        let idx = i.0 % l;
        let cur = (self.next - 1) % l;

        let loop_i = i.0 / l;
        let loop_c = (self.next - 1) / l;

        if idx < cur {
            // need to check that self.next hasn't looped.
            if loop_i != loop_c {
                return None;
            }
        } else {
            // need to check that i is from previous loop.
            if loop_c > 0 && loop_i != loop_c - 1 {
                return None;
            }
        }

        Some(idx as usize)
    }

    pub fn get(&self, i: Ident) -> Option<&T> {
        let idx = self.index_in_scope(i)?;
        self.buffer[idx].as_ref()
    }

    pub fn get_mut(&mut self, i: Ident) -> Option<&mut T> {
        let idx = self.index_in_scope(i)?;
        self.buffer[idx].as_mut()
    }

    pub fn first(&self) -> Option<&T> {
        let loop_c = (self.next - 1) / self.len as u64;

        let i = if loop_c == 0 {
            0
        } else {
            (self.next % self.len as u64) as usize
        };

        self.buffer[i].as_ref()
    }

    pub fn last(&self) -> Option<&T> {
        let l = self.len as u64;
        let idx = (l + self.next - 1) % l;
        self.buffer[idx as usize].as_ref()
    }

    pub fn len(&self) -> usize {
        let loop_c = (self.next - 1) / self.len as u64;

        if loop_c == 0 {
            (self.next % self.len as u64) as usize
        } else {
            self.len
        }
    }
}

impl PacketizingBuffer {
    pub(crate) fn new(pack: CodecPacketizer, max_retain: usize) -> Self {
        PacketizingBuffer {
            pack,
            queue: RingBuf::new(max_retain),
            by_seq: HashMap::new(),
            by_size: BTreeMap::new(),

            emit_next: Ident::default(),
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

            let previous_data = self.queue.last().map(|p| p.data.as_slice());
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

            let (ident, evicted) = self.queue.push(rtp);

            if let Some(evicted) = evicted {
                self.handle_evicted(now, evicted);
            }

            // TODO...
        }

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

        let (ident, evicted) = self.queue.push(rtp);

        if let Some(evicted) = evicted {
            self.handle_evicted(now, evicted);
        }

        // TODO
    }

    fn handle_evicted(&mut self, now: Instant, p: Packetized) {
        if p.count_as_unsent {
            let queue_time = now - p.queued_at;
            self.total.decrease(p.data.len(), queue_time);
        }

        if let Some(seq_no) = p.seq_no {
            self.by_seq.remove(&seq_no);
        }
    }

    pub fn maybe_next(&self) -> Option<&Packetized> {
        self.queue.get(self.emit_next)
    }

    pub fn update_next(&mut self, seq_no: SeqNo) {
        let id = self.emit_next;

        let next = self
            .queue
            .get_mut(id)
            .expect("update_next_seq_no to be called after maybe_next");

        self.by_seq.insert(seq_no, id);

        let key = next.data.len() % SIZE_BUCKET;
        self.by_size.insert(key, id);

        next.seq_no = Some(seq_no);
    }

    pub fn take_next(&mut self, now: Instant) -> &Packetized {
        self.total.move_time_forward(now);

        let next = self
            .queue
            .get_mut(self.emit_next)
            .expect("take_next to be called after maybe_next");

        if next.count_as_unsent {
            next.count_as_unsent = false;
            let queue_time = now - next.queued_at;
            self.total.decrease(next.data.len(), queue_time);
        }

        self.emit_next = self.emit_next.increase();
        self.last_emit = Some(now);

        next
    }

    pub fn get(&self, seq_no: SeqNo) -> Option<&Packetized> {
        let id = self.by_seq.get(&seq_no)?;
        self.queue.get(*id)
    }

    pub fn has_ssrc(&self, ssrc: Ssrc) -> bool {
        self.queue
            .first()
            .map(|p| p.meta.ssrc == ssrc)
            .unwrap_or(false)
    }

    pub fn first_seq_no(&self) -> Option<SeqNo> {
        self.queue.first().and_then(|p| p.seq_no)
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
        self.queue.len()
    }

    /// Find a historic packet that is smaller than the given max_size.
    pub fn historic_packet_smaller_than(&self, max_size: usize) -> Option<&Packetized> {
        self.by_size
            .range(..=max_size)
            .rev()
            .next()
            .and_then(|(_, id)| self.queue.get(*id))
    }

    /// Should only be called after has_next() which ensures there is a packet to get the SSRC from.
    pub fn ssrc(&self) -> Ssrc {
        self.queue
            .first()
            .expect("a packet for ssrc call")
            .meta
            .ssrc
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
