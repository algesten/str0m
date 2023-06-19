use std::collections::{BTreeMap, VecDeque};
use std::collections::{BinaryHeap, HashMap};

use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp::{ExtensionValues, MediaTime, Rid, RtpHeader, SeqNo, Ssrc};

use super::ring::Ident;
use super::ring::RingBuf;
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

const SIZE_BUCKET: usize = 25;
#[derive(Debug)]
pub struct PacketizingBuffer {
    pack: CodecPacketizer,

    /// The packets that are currently retained, either because they are queued or for RTX
    /// purposes.
    packets: HashMap<Ident, Packetized>,
    /// The queue of unset packets to send.
    queue: VecDeque<QueueItem>,
    /// RTX mapping.
    by_seq: BTreeMap<SeqNo, Ident>,
    /// Packets of various sizes to quick fulfill spurious RTX for padding,
    by_size: [Option<Ident>; 1200 / SIZE_BUCKET],

    next_ident: Ident,

    last_emit: Option<Instant>,
    // The max size the queue is allowed to grow to.
    max_queue_size: usize,
    // The number of packets retained for RTX.
    rtx_retain: usize,

    total: TotalQueue,

    // Set when we first discover the SSRC
    ssrc: Option<Ssrc>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct QueueItem {
    queued_at: Instant,
    ident: Ident,
}

impl PacketizingBuffer {
    pub(crate) fn new(pack: CodecPacketizer, max_queue_size: usize, rtx_retain: usize) -> Self {
        PacketizingBuffer {
            pack,
            packets: HashMap::with_capacity(max_queue_size / 4),
            queue: Default::default(),
            by_seq: Default::default(),
            by_size: [None; 1200 / SIZE_BUCKET],

            last_emit: None,
            max_queue_size,
            rtx_retain,

            total: TotalQueue::default(),
            ssrc: None,
            next_ident: Default::default(),
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
        self.total.move_time_forward(now);

        assert!(
            len <= self.max_queue_size,
            "Data larger than send buffer {} > {}",
            data.len(),
            self.max_queue_size
        );

        let mut data_len = 0;

        if self.ssrc.is_none() {
            self.ssrc = Some(meta.ssrc);
        }

        let mut overflow = false;
        for (idx, data) in chunks.into_iter().enumerate() {
            let first = idx == 0;
            let last = idx == len - 1;

            let previous_data =
                peek_next(&mut self.queue, &mut self.packets).map(|p| p.data.as_slice());
            let marker = self.pack.is_marker(data.as_slice(), previous_data, last);

            self.total.increase(now, Duration::ZERO, data.len());
            data_len += data.len();

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

            let (ident, evicted) = self.do_push(rtp, now);
            overflow |= evicted.is_some();

            if let Some(evicted) = evicted {
                self.handle_evicted(now, evicted);
            }
        }

        if overflow {
            warn!("Send buffer overflow, increase send buffer size");
        }

        Ok(overflow)
    }

    pub fn push_rtp_packet(
        &mut self,
        now: Instant,
        data: Vec<u8>,
        meta: PacketizedMeta,
        rtp_header: RtpHeader,
    ) -> bool {
        self.total.move_time_forward(now);

        self.total.increase(now, Duration::ZERO, data.len());

        if self.ssrc.is_none() {
            self.ssrc = Some(meta.ssrc);
        }

        let data_len = data.len();

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

        let (ident, evicted) = self.do_push(rtp, now);
        let overflow = evicted.is_some();

        if let Some(evicted) = evicted {
            self.handle_evicted(now, evicted);
        }

        overflow
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

    pub fn peek_next(&self) -> Option<&Packetized> {
        peek_next(&self.queue, &self.packets)
    }

    pub fn pop_next(&mut self, seq_no: SeqNo, now: Instant) -> &Packetized {
        let next_item = self
            .queue
            .pop_front()
            .expect("take_next to be called after peek_next");

        let packet = self.handle_pop(next_item, seq_no, now);

        packet
    }

    pub fn get(&self, seq_no: SeqNo) -> Option<&Packetized> {
        let id = self.by_seq.get(&seq_no)?;
        self.packets.get(id)
    }

    pub fn first_seq_no(&self) -> Option<SeqNo> {
        self.peek_next().and_then(|p| p.seq_no)
    }

    pub fn queue_snapshot(&mut self, now: Instant) -> QueueSnapshot {
        self.total.move_time_forward(now);

        QueueSnapshot {
            created_at: now,
            size: self.total.unsent_size,
            packet_count: self.total.unsent_count as u32,
            total_queue_time_origin: self.total.queue_time,
            last_emitted: self.last_emit,
            first_unsent: self.peek_next().map(|p| p.queued_at),
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
        let key = max_size / SIZE_BUCKET;

        (0..key)
            .rev()
            .find_map(|i| self.by_size[i].and_then(|id| self.packets.get(&id)))
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc.expect("Send buffer to have an SSRC")
    }

    fn do_push(&mut self, rtp: Packetized, now: Instant) -> (Ident, Option<Packetized>) {
        let evicted = self.maybe_evict();

        let ident = self.next_ident();
        self.packets.insert(ident, rtp);
        self.queue.push_back(QueueItem {
            queued_at: now,
            ident,
        });

        (ident, evicted)
    }

    fn maybe_evict(&mut self) -> Option<Packetized> {
        if self.queue.len() < self.max_queue_size {
            return None;
        }

        let item = self.queue.pop_front().unwrap();
        let packet = self.packets.remove(&item.ident);

        if let Some(seq_no) = packet.as_ref().and_then(|p| p.seq_no) {
            self.by_seq.remove(&seq_no);
        }

        packet
    }

    fn next_ident(&mut self) -> Ident {
        let previous = self.next_ident;
        self.next_ident = self.next_ident.increase();

        previous
    }

    fn handle_pop(&mut self, next_item: QueueItem, seq_no: SeqNo, now: Instant) -> &Packetized {
        self.total.move_time_forward(now);

        let packet = self
            .packets
            .get_mut(&next_item.ident)
            .expect("take_next to be called after peek_next");

        if self.by_seq.len() >= self.rtx_retain {
            // Get rid of the oldest RTX packet.
            self.by_seq.pop_first();
        }
        self.by_seq.insert(seq_no, next_item.ident);

        let key = packet.data.len() / SIZE_BUCKET;
        self.by_size[key] = Some(next_item.ident);
        packet.seq_no = Some(seq_no);

        if packet.count_as_unsent {
            packet.count_as_unsent = false;
            let queue_time = now - packet.queued_at;
            self.total.decrease(packet.data.len(), queue_time);
        }
        self.last_emit = Some(now);

        packet
    }
}

fn peek_next<'p>(
    queue: &VecDeque<QueueItem>,
    packets: &'p HashMap<Ident, Packetized>,
) -> Option<&'p Packetized> {
    queue.front().and_then(|q| packets.get(&q.ident))
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
