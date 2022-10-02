use std::collections::VecDeque;
use std::time::Instant;

use crate::{MediaTime, SeqNo, Ssrc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Twcc {
    pub sender_ssrc: Ssrc,
    pub ssrc: Ssrc,
    pub feedback_count: u8, // counter for each Twcc
    pub base_seq: u16,
    pub status_count: u16,
    pub reference_time: u32, // 24 bit
    pub chunks: Vec<PacketChunk>,
    pub delta: Vec<Delta>,
}

// 1 1 1 1 1 0 0 0 0 1 1 1 1
// |-------| |-------------|
// T1
//         T2 ------ T

#[derive(Debug)]
pub struct TwccRegister {
    // How many packets to keep when they are reported. This is to handle packets arriving out
    // of order and where two consecutive calls to `build_report` needs to go "backwards" in
    // base_seq.
    keep_reported: usize,

    /// Queue of packets to form Twcc reports of.
    ///
    /// Once the queue has some content, we will always keep at least one entry to "remember" for the
    /// next report.
    queue: VecDeque<Receiption>,

    /// The point in time we consider 0. All reported values are offset from this. Set to first
    /// unreported packet in first `build_reported`.
    ///
    // https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01#page-5
    // reference time: 24 bits Signed integer indicating an absolute
    // reference time in some (unknown) time base chosen by the
    // sender of the feedback packets.
    time_start: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Receiption {
    seq: SeqNo,
    time: Instant,
    reported: bool,
}

impl TwccRegister {
    pub fn new(keep_reported: usize) -> Self {
        TwccRegister {
            keep_reported,
            queue: VecDeque::new(),
            time_start: None,
        }
    }

    pub fn max_seq(&self) -> SeqNo {
        self.queue
            .iter()
            .map(|r| r.seq)
            .max_by_key(|r| *r)
            .unwrap_or(0.into())
    }

    pub fn update_seq(&mut self, seq: SeqNo, time: Instant) {
        match self.queue.binary_search_by_key(&seq, |r| r.seq) {
            Ok(_) => {
                // Exact same SeqNo found. This is an error where the sender potentially
                // used the same twcc sequence number for two packets. Let's ignore it.
            }
            Err(idx) => {
                self.queue.insert(
                    idx,
                    Receiption {
                        seq,
                        time,
                        reported: false,
                    },
                );
            }
        }
    }

    pub fn build_report(&mut self) -> Option<Twcc> {
        // First unreported sets the time_start relative offset.
        let first = self.queue.iter().skip_while(|r| r.reported).next()?;

        if self.time_start.is_none() {
            self.time_start = Some(first.time);
        }

        let (base_seq, base_time) = (first.seq, first.time);
        let base_time_rel = base_time - self.time_start.expect("a start time");
        let mut base_time_m: MediaTime = base_time_rel.into();

        // The value is to be interpreted in multiples of 64ms
        // 1000_000/64 = 15_625
        const TIME_24_BASE: i64 = 15_625;
        base_time_m = base_time_m.rebase(TIME_24_BASE);

        let reference_time = (base_time_m.numer() / 1000) as u32;

        let mut twcc = Twcc {
            sender_ssrc: 0.into(),
            ssrc: 0.into(),
            feedback_count: 0,
            base_seq: *base_seq as u16,
            reference_time,
            status_count: 0,
            chunks: Vec::new(),
            delta: Vec::new(),
        };

        let interims = self.build_interims(base_seq, base_time);
        let mut start = 0;

        loop {
            if start >= interims.len() {
                break;
            }

            // attempt to pack the interims in different ways to see which way consumes most chunk interims.
            let as_run = PacketChunk::pack_as_run(&interims[start..]);
            let as_single = PacketChunk::pack_as_single(&interims[start..]);
            let as_double = PacketChunk::pack_as_double(&interims[start..]);

            let max = as_run.max(as_single).max(as_double);

            assert!(max > 0);
            let stop = start + max;

            let mut chunk = if max == as_run {
                let status = interims[start].status();
                PacketChunk::Run(status, 0)
            } else if max == as_single {
                PacketChunk::Vector(Symbol::Single(0))
            } else if max == as_double {
                PacketChunk::Vector(Symbol::Double(0))
            } else {
                unreachable!()
            };

            for i in start..stop {
                if let Some((index, delta)) = chunk.append(interims[i]) {
                    // Mark the reception as reported.
                    let r = self.queue.get_mut(index).expect("reception for index");
                    r.reported = true;

                    twcc.delta.push(delta);
                }
            }
            twcc.chunks.push(chunk);

            start = stop;
        }

        // How many reported we have from the beginning of the queue.
        let reported_count = self.queue.iter().skip_while(|r| r.reported).count();

        // clean up
        if reported_count > self.keep_reported {
            let to_remove = reported_count - self.keep_reported;
            self.queue.drain(..to_remove);
        }

        Some(twcc)
    }

    /// Interims are deltas between `Receiption` which is an intermediary format before
    /// we populate the Twcc report.
    fn build_interims(&self, base_seq: SeqNo, base_time: Instant) -> Vec<ChunkInterim> {
        let report_from = self
            .queue
            .iter()
            .enumerate()
            .skip_while(|(_, r)| r.reported);

        let mut prev = (base_seq, base_time);
        let mut interims = Vec::new();

        for (index, r) in report_from {
            let diff_seq = *r.seq - *prev.0;

            if diff_seq > 1 {
                for range in (0..diff_seq).step_by(8192) {
                    // max 2^13 run length in each missing chunk
                    interims.push(ChunkInterim::Missing(range as u16));
                }
                continue;
            }

            let diff_time = if r.time < prev.1 {
                // negative
                let dur = prev.1 - r.time;
                dur.as_micros() as i32
            } else {
                let dur = r.time - prev.1;
                dur.as_micros() as i32
            };

            let (status, time) = if diff_time < -8192_000 || diff_time > 8191_750 {
                // This is too large to be representable in deltas.
                // Abort, make a report of what we got, and start anew.
                break;
            } else if diff_time < 0 || diff_time > 63_750 {
                let t = diff_time / 250;
                assert!(t >= -32_765 && t <= 32_767);
                (PacketStatus::ReceivedLargeOrNegativeDelta, t as i16)
            } else {
                let t = diff_time / 250;
                assert!(t >= 0 && t <= 255);
                (PacketStatus::ReceivedSmallDelta, t as i16)
            };

            interims.push(ChunkInterim::Received(index, status, time));
            prev = (r.seq, r.time);
        }

        interims
    }
}

#[derive(Debug, Clone, Copy)]
enum ChunkInterim {
    Missing(u16), // max 2^13 (one run length)
    Received(usize, PacketStatus, i16),
}

impl ChunkInterim {
    fn status(&self) -> PacketStatus {
        match self {
            ChunkInterim::Missing(_) => PacketStatus::NotReceived,
            ChunkInterim::Received(_, s, _) => *s,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketChunk {
    Run(PacketStatus, u16), // 13 bit repeat
    Vector(Symbol),
}

impl PacketChunk {
    fn pack_as_run(interims: &[ChunkInterim]) -> usize {
        assert!(!interims.is_empty());

        let status = interims[0].status();

        interims.iter().take_while(|i| i.status() == status).count()
    }

    fn pack_as_single(interims: &[ChunkInterim]) -> usize {
        assert!(!interims.is_empty());

        let mut space = 0;
        let mut last_index = 0;

        for (index, i) in interims.iter().enumerate() {
            match i {
                ChunkInterim::Missing(n) => {
                    if space + n <= 14 {
                        space += n;
                    } else {
                        // doesn't fit
                        break;
                    }
                }
                ChunkInterim::Received(_, status, _) => match status {
                    PacketStatus::ReceivedSmallDelta => {
                        if space + 1 <= 14 {
                            space += 1
                        } else {
                            // doesn't fit.
                            break;
                        }
                    }
                    PacketStatus::ReceivedLargeOrNegativeDelta => {
                        // TODO: confirm the correct logic for Single is that it only counts large deltas?
                        break;
                    }
                    _ => unreachable!(),
                },
            }
            last_index = index;
        }

        last_index
    }

    fn pack_as_double(interims: &[ChunkInterim]) -> usize {
        assert!(!interims.is_empty());

        let mut space = 0;
        let mut last_index = 0;

        for (index, i) in interims.iter().enumerate() {
            match i {
                ChunkInterim::Missing(n) => {
                    if space + n <= 7 {
                        space += n;
                    } else {
                        // doesn't fit
                        break;
                    }
                }
                ChunkInterim::Received(_, status, _) => match status {
                    PacketStatus::ReceivedSmallDelta
                    | PacketStatus::ReceivedLargeOrNegativeDelta => {
                        if space <= 7 {
                            space += 1
                        } else {
                            // doesn't fit.
                            break;
                        }
                    }
                    _ => unreachable!(),
                },
            }
            last_index = index;
        }

        last_index
    }

    fn append(&mut self, i: ChunkInterim) -> Option<(usize, Delta)> {
        use ChunkInterim::*;
        use PacketChunk::*;
        match (self, i) {
            (Run(s, c), Missing(n)) => {
                assert!(*s == PacketStatus::NotReceived);
                *c += n;
                assert!(*c <= 8192);
                None
            }
            (Run(s, c), Received(i, s2, t)) => {
                assert!(*s == s2);
                *c += 1;
                assert!(*c <= 8192);
                if *s == PacketStatus::ReceivedSmallDelta {
                    assert!(t >= 0 && t <= 255);
                    Some((i, Delta::Small(t as u8)))
                } else if *s == PacketStatus::ReceivedLargeOrNegativeDelta {
                    Some((i, Delta::Large(t)))
                } else {
                    unreachable!()
                }
            }
            (Vector(Symbol::Single(v)), Missing(c)) => {
                // The RFC says:
                // "packet received" (0) and "packet not received" (1)
                // but I'm not sure I trust it. 0 for packet not received is consistent with
                // the example given in the RFC and would align it with two bit packet status
                // having 00 as not received.
                assert!(c < 14);
                *v <<= c;
                None
            }
            (Vector(Symbol::Single(v)), Received(i, s2, t)) => {
                *v <<= 1;
                *v |= 1;
                assert!(s2 == PacketStatus::ReceivedSmallDelta);
                assert!(t >= 0 && t <= 255);
                Some((i, Delta::Small(t as u8)))
            }
            (Vector(Symbol::Double(v)), Missing(c)) => {
                assert!(c < 7);
                *v <<= c * 2;
                None
            }
            (Vector(Symbol::Double(v)), Received(i, s2, t)) => {
                *v <<= 2;
                *v |= s2 as u16;
                assert!(s2 == PacketStatus::ReceivedLargeOrNegativeDelta);
                if s2 == PacketStatus::ReceivedSmallDelta {
                    Some((i, Delta::Small(t as u8)))
                } else if s2 == PacketStatus::ReceivedLargeOrNegativeDelta {
                    Some((i, Delta::Large(t)))
                } else {
                    unreachable!()
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketStatus {
    NotReceived = 0b00,
    ReceivedSmallDelta = 0b01,
    ReceivedLargeOrNegativeDelta = 0b10,
    Unknown = 0b11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbol {
    Single(u16),
    Double(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delta {
    Small(u8),
    Large(i16),
}

impl Into<u8> for PacketStatus {
    fn into(self) -> u8 {
        self as usize as u8
    }
}

impl From<u8> for PacketStatus {
    fn from(v: u8) -> Self {
        match v {
            0b00 => Self::NotReceived,
            0b01 => Self::ReceivedSmallDelta,
            0b10 => Self::ReceivedLargeOrNegativeDelta,
            _ => Self::Unknown,
        }
    }
}
