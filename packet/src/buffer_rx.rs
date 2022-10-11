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
    depack: CodecDepacketizer,
    last_emitted: Option<SeqNo>,
    queue: VecDeque<Entry>,
}

impl DepacketizingBuffer {
    pub fn new(depack: CodecDepacketizer) -> Self {
        DepacketizingBuffer {
            depack,
            last_emitted: None,
            queue: VecDeque::new(),
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
                return;
            }
            Err(i) => {
                // i is insertion point to maintain order
                self.queue.insert(i, Entry { meta, data });
            }
        }
    }

    pub fn emit_sample(&mut self) -> Option<Result<Depacketized, PacketError>> {
        let (start, stop) = self.find_contiguous()?;

        let mut data = Vec::new();

        let time = self.queue.get(start).expect("first index exist").meta.time;
        let mut meta = Vec::with_capacity(stop - start + 1);

        for entry in self.queue.drain(start..=stop) {
            if let Err(e) = self.depack.depacketize(&entry.data, &mut data) {
                return Some(Err(e));
            }
            self.last_emitted = Some(entry.meta.seq_no);
            meta.push(entry.meta);
        }

        // Clean out stuff that is now too old.
        let last = self.last_emitted.expect("there to be a last emitted");
        self.queue.retain(|r| r.meta.seq_no > last);

        let dep = Depacketized { time, meta, data };
        Some(Ok(dep))
    }

    fn find_contiguous(&self) -> Option<(usize, usize)> {
        let mut start = None;
        let mut offset = 0;
        let mut stop = None;

        for (index, entry) in self.queue.iter().enumerate() {
            // We are not emitting older samples.
            if let Some(last) = self.last_emitted {
                if entry.meta.seq_no <= last {
                    continue;
                }
            }

            let index = index as i64;
            let iseq = *entry.meta.seq_no as i64;

            if self.depack.is_partition_head(&entry.data) {
                start = Some(index);
                offset = iseq - index;
                stop = None;
            } else {
                if start.is_some() {
                    if index + offset != iseq {
                        // packets are not contiguous.
                        start = None;
                        stop = None;
                        continue;
                    }
                }
            }

            if self
                .depack
                .is_partition_tail(entry.meta.header.marker, &entry.data)
            {
                stop = Some(index);
            }

            if let (Some(start), Some(stop)) = (start, stop) {
                // we found a contiguous sequence of packets.
                return Some((start as usize, stop as usize));
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

#[derive(Debug)]
struct TestDepacketizer;

impl Depacketizer for TestDepacketizer {
    fn depacketize(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), PacketError> {
        out.extend_from_slice(packet);
        Ok(())
    }

    fn is_partition_head(&self, packet: &[u8]) -> bool {
        !packet.is_empty() && packet[0] % 3 == 1
    }

    fn is_partition_tail(&self, marker: bool, packet: &[u8]) -> bool {
        if packet.is_empty() {
            return false;
        }

        let is_tail = packet[0] % 3 == 0;
        if is_tail {
            assert!(marker);
        }
        is_tail
    }
}
