use std::collections::VecDeque;
use std::fmt;
use std::time::Instant;

use rtp::{MediaTime, RtpHeader, SeqNo};

use crate::{CodecDepacketizer, Depacketizer, PacketError};

#[derive(Clone, PartialEq, Eq)]
/// Holds metadata incoming RTP data.
pub struct RtpMeta {
    pub received: Instant,
    pub time: MediaTime,
    pub seq_no: SeqNo,
    pub header: RtpHeader,
}

#[derive(Clone)]
pub struct Depacketized {
    pub time: MediaTime,
    pub meta: Vec<RtpMeta>,
    pub data: Vec<u8>,
}

#[derive(Debug)]
struct Entry {
    emitted: bool,
    meta: RtpMeta,
    data: Vec<u8>,
}

impl RtpMeta {
    pub fn new(received: Instant, time: MediaTime, seq_no: SeqNo, header: RtpHeader) -> Self {
        RtpMeta {
            received,
            time,
            seq_no,
            header,
        }
    }
}

#[derive(Debug)]
pub struct DepacketizingBuffer {
    hold_back: usize,
    depack: CodecDepacketizer,
    last_emitted: Option<SeqNo>,
    queue: VecDeque<Entry>,
    segments: Vec<(usize, usize)>,
}

impl DepacketizingBuffer {
    pub fn new(depack: CodecDepacketizer, hold_back: usize) -> Self {
        DepacketizingBuffer {
            hold_back,
            depack,
            last_emitted: None,
            queue: VecDeque::new(),
            segments: Vec::new(),
        }
    }

    pub fn push(&mut self, meta: RtpMeta, data: Vec<u8>) {
        // We're not emitting samples in the wrong order. If we receive
        // packets that are before the last emitted, we drop.
        if let Some(last_emitted) = self.last_emitted {
            if meta.seq_no <= last_emitted {
                trace!("Drop before emitted: {} <= {}", meta.seq_no, last_emitted);
                return;
            }
        }

        match self
            .queue
            .binary_search_by_key(&meta.seq_no, |r| r.meta.seq_no)
        {
            Ok(_) => {
                // exact same seq_no found. ignore
                trace!("Drop exactly same packet: {}", meta.seq_no);
            }
            Err(i) => {
                // i is insertion point to maintain order
                let entry = Entry {
                    emitted: false,
                    meta,
                    data,
                };
                self.queue.insert(i, entry);
            }
        }
    }

    pub fn emit_sample(&mut self) -> Option<Result<Depacketized, PacketError>> {
        self.update_segments();
        let (start, stop) = self.segments.first()?;

        let first_entry = self.queue.get(*start).expect("entry for start index");

        let is_following_last_emitted = self
            .last_emitted
            .map(|l| l.is_next(first_entry.meta.seq_no))
            .unwrap_or(true);

        let is_more_than_hold_back = self.segments.len() >= self.hold_back;

        // We prefer to just release samples because they are following the last emitted.
        // However as fallback, we "hold back" samples to let RTX mechanics fill in potential
        // gaps in the RTP sequences before letting go.
        if !is_following_last_emitted && !is_more_than_hold_back {
            return None;
        }

        let mut data = Vec::new();

        let time = self.queue.get(*start).expect("first index exist").meta.time;
        let mut meta = Vec::with_capacity(stop - start + 1);

        for entry in self.queue.range_mut(*start..=*stop) {
            if let Err(e) = self.depack.depacketize(&entry.data, &mut data) {
                return Some(Err(e));
            }
            entry.emitted = true;
            self.last_emitted = Some(entry.meta.seq_no);
            meta.push(entry.meta.clone());
        }

        // We're not going to emit samples in the incorrect order, there's no point in keeping
        // stuff before the emitted range.
        self.queue.drain(0..=*stop);

        let dep = Depacketized { time, meta, data };
        Some(Ok(dep))
    }

    fn update_segments(&mut self) -> Option<(usize, usize)> {
        self.segments.clear();

        #[derive(Clone, Copy)]
        struct Start {
            index: i64,
            time: MediaTime,
            offset: i64,
        }

        let mut start: Option<Start> = None;
        let last_emitted = self.last_emitted.unwrap_or(0.into());

        for (index, entry) in self.queue.iter().enumerate() {
            // We are not emitting older samples.
            if entry.emitted || entry.meta.seq_no <= last_emitted {
                continue;
            }

            let index = index as i64;
            let iseq = *entry.meta.seq_no as i64;
            let expected_seq = start.map(|s| s.offset + index);

            let is_expected_seq = expected_seq == Some(iseq);
            let is_same_timestamp = start.map(|s| s.time) == Some(entry.meta.time);
            let is_defacto_tail = is_expected_seq && !is_same_timestamp;

            if start.is_some() && is_defacto_tail {
                // We found a segment that ended because the timestamp changed without
                // a gap in the sequence number. The marker bit in the RTP packet is
                // just indicative, this is the robust fallback.
                let segment = (start.unwrap().index as usize, index as usize - 1);
                self.segments.push(segment);
                start = None;
            }

            if start.is_some() && (!is_expected_seq || !is_same_timestamp) {
                // Not contiguous. Start looking again.
                start = None;
            }

            // Each segment can have multiple is_partition_head() == true, record the first.
            if start.is_none() && self.depack.is_partition_head(&entry.data) {
                start = Some(Start {
                    index,
                    time: entry.meta.time,
                    offset: iseq - index,
                });
            }

            let is_tail = self
                .depack
                .is_partition_tail(entry.meta.header.marker, &entry.data);

            if start.is_some() && is_tail {
                // We found a contiguous sequence of packets ending with something from
                // the packet (like the RTP marker bit) indicating it's the tail.
                let segment = (start.unwrap().index as usize, index as usize);
                self.segments.push(segment);
                start = None;
            }
        }

        None
    }
}

impl fmt::Debug for RtpMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtpMeta")
            .field("received", &self.received)
            .field("time", &self.time)
            .field("seq_no", &self.seq_no)
            .field("header", &self.header)
            .finish()
    }
}

impl fmt::Debug for Depacketized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sample")
            .field("time", &self.time)
            .field("meta", &self.meta)
            .field("data", &self.data.len())
            .finish()
    }
}
