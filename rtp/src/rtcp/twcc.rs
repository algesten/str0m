use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::{FeedbackMessageType, RtcpHeader, RtcpPacket};
use crate::{RtcpType, SeqNo, Ssrc, TransportType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Twcc {
    pub sender_ssrc: Ssrc,
    pub ssrc: Ssrc,
    pub base_seq: u16,
    pub status_count: u16,
    pub reference_time: u32, // 24 bit
    pub feedback_count: u8,  // counter for each Twcc
    pub chunks: Vec<PacketChunk>,
    pub delta: Vec<Delta>,
}

impl Twcc {
    fn chunks_byte_len(&self) -> usize {
        self.chunks.len() * 2
    }

    fn delta_byte_len(&self) -> usize {
        self.delta.iter().map(|d| d.byte_len()).sum()
    }
}

impl RtcpPacket for Twcc {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::TransportLayerFeedback,
            feedback_message_type: FeedbackMessageType::TransportFeedback(
                TransportType::TransportWide,
            ),
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        // header: 1
        // sender ssrc: 1
        // ssrc: 1
        // base seq + packet status: 1
        // ref time + feedback count: 1
        // chunks byte len + delta byte len + padding

        let mut total = self.chunks_byte_len() + self.delta_byte_len();

        let pad = 4 - total % 4;
        if pad < 4 {
            total += pad;
        }

        assert!(total % 4 == 0);

        let total_words = total / 4;

        5 + total_words
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        let len_start = buf.len();

        self.header().write_to(buf);
        (&mut buf[4..8]).copy_from_slice(&self.sender_ssrc.to_be_bytes());
        (&mut buf[8..12]).copy_from_slice(&self.ssrc.to_be_bytes());

        (&mut buf[12..14]).copy_from_slice(&self.base_seq.to_be_bytes());
        (&mut buf[14..16]).copy_from_slice(&self.status_count.to_be_bytes());

        (&mut buf[16..19]).copy_from_slice(&self.reference_time.to_be_bytes()[0..3]);
        buf[19] = self.feedback_count;

        let mut buf = &mut buf[20..];
        for p in &self.chunks {
            p.write_to(buf);
            buf = &mut buf[2..];
        }

        for d in &self.delta {
            let n = d.write_to(buf);
            buf = &mut buf[n..];
        }

        let mut total = len_start - buf.len();

        let pad = 4 - total % 4;
        if pad < 4 {
            for i in 0..pad {
                buf[total + i] = 0;
            }
            total += pad;
        }

        total
    }
}

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

    pub fn build_report(&mut self, max_byte_size: usize) -> Option<Twcc> {
        // First unreported is the self.time_start relative offset of the next Twcc.
        let first = self.queue.iter().skip_while(|r| r.reported).next()?;

        // Set once on first ever built report.
        if self.time_start.is_none() {
            self.time_start = Some(first.time);
        }

        let (base_seq, first_time) = (first.seq, first.time);
        let time_start = self.time_start.expect("a start time");

        // The difference between our Twcc reference time and the first ever report start time.
        let first_time_rel = first_time - time_start;

        // The value is to be interpreted in multiples of 64ms.
        let reference_time = (first_time_rel.as_micros() as u64 / 64_000) as u32;

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

        // Because reference time is in steps of 64ms, the first reported packet might have an
        // offset (packet time resolution is 250us). This base_time is calculated backwards from
        // reference time so that we can offset all packets from the "truncated" 64ms steps.
        // The RFC says:
        // The first recv delta in this packet is relative to the reference time.
        let base_time = time_start + Duration::from_micros(reference_time as u64 * 64_000);

        // The ChunkInterim are helpers structures that hold the deltas between
        // the registered receptions.
        let interims = self.build_interims(base_seq, base_time);

        // Index into interims where we are to report from.
        let mut start = 0;

        // How many packet statuses we've included in the report so far.
        let mut status_count = 0;

        // 20 bytes is the size of the fixed fields in Twcc.
        let mut bytes_left = max_byte_size - 20;

        loop {
            // If we reach end of the interims, stop.
            if start >= interims.len() {
                break;
            }

            // If there is no space left for at least one more chunk + delta, stop.
            // 2 byte chunk + 2 byte delta + 3 byte padding
            if bytes_left < 7 {
                break;
            }

            // Attempt to pack the interims in different ways to see which way consumes most chunk interims.
            let as_run = PacketChunk::pack_as_run(&interims[start..]);
            let as_single = PacketChunk::pack_as_single(&interims[start..]);
            let as_double = PacketChunk::pack_as_double(&interims[start..]);

            let max = as_run.max(as_single).max(as_double);

            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            enum Mode {
                Run,
                Single,
                Double,
            }

            // Pick a mode for packing chunks.
            let mode = if max == as_run {
                Mode::Run
            } else if max == as_single {
                Mode::Single
            } else {
                Mode::Double
            };

            assert!(max > 0);
            let stop = start + max;

            // The next chunk, depending on mode.
            let mut chunk = match mode {
                Mode::Run => {
                    let status = interims[start].status();
                    PacketChunk::Run(status, 0)
                }
                Mode::Single => {
                    assert!(max <= 14);
                    PacketChunk::Vector(Symbol::Single(0))
                }
                Mode::Double => {
                    assert!(max <= 7);
                    PacketChunk::Vector(Symbol::Double(0))
                }
            };

            // How many status counts we've actually appended in the chunk far. This might be lower
            // than max, if we abort the appending due to running out of bytes_left.
            let mut appended_in_chunk = 0;

            for i in start..stop {
                if bytes_left < 7 {
                    break;
                }
                if let Some((index, delta)) = chunk.append(interims[i]) {
                    // Mark the reception as reported.
                    let r = self.queue.get_mut(index).expect("reception for index");
                    r.reported = true;

                    twcc.delta.push(delta);
                    bytes_left -= delta.byte_len();
                }
                appended_in_chunk += interims[i].status_count();
                status_count += interims[i].status_count();
                bytes_left -= 2;
            }

            // Because we bit shift the single/double for each appended interim, we must
            // ensure the entire single/double is "full" by filling with 0 to 14 or 7*2 respective.
            match mode {
                Mode::Single => {
                    let n = 14 - appended_in_chunk;
                    chunk.append(ChunkInterim::Missing(n as u16));
                }
                Mode::Double => {
                    let n = 7 - appended_in_chunk;
                    chunk.append(ChunkInterim::Missing(n as u16));
                }
                _ => {}
            }

            twcc.chunks.push(chunk);

            start = stop;
        }

        twcc.status_count = status_count;

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
                let mut todo = diff_seq - 1;
                while todo > 0 {
                    // max 2^13 run length in each missing chunk
                    let n = todo.min(8192);
                    interims.push(ChunkInterim::Missing(n as u16));
                    todo -= n;
                }
            }

            let diff_time = if r.time < prev.1 {
                // negative
                let dur = prev.1 - r.time;
                dur.as_micros() as i32 * -1
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

    fn status_count(&self) -> u16 {
        match self {
            ChunkInterim::Missing(n) => *n,
            ChunkInterim::Received(_, _, _) => 1,
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
        let mut remaining = 8192; // each run can be max 2^13
        let mut taken = 0;

        for i in interims {
            let status_count = i.status_count() as i32;
            if i.status() != status || remaining - status_count < 0 {
                break;
            }
            remaining -= status_count;
            taken += 1;
        }

        taken
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
                        // Confirmed in email with Erik Sprang.
                        // "The intent is to just truncate the 2-bit values"
                        // Which means 01 (received small delta) becomes 1.
                        break;
                    }
                    _ => unreachable!(),
                },
            }
            last_index = index;
        }

        last_index + 1
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

        last_index + 1
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
                // Confirmed in email that despite the RFC, 0 is not received and 1 is received (small delta).
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

    fn write_to(&self, buf: &mut [u8]) {
        let x = match self {
            //     0                   1
            //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
            //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //    |T| S |       Run Length        |
            //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // chunk type (T):  1 bit A zero identifies this as a run length chunk.
            // packet status symbol (S):  2 bits The symbol repeated in this run.
            //             See above.
            // run length (L):  13 bits An unsigned integer denoting the run length.
            PacketChunk::Run(s, n) => {
                let mut x = 0_u16;
                x |= (*s as u16) << 13;
                assert!(*n <= 8192);
                x |= n;
                x
            }

            // Corrected according to email exchange at the bottom..
            //
            //         0                   1
            //         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
            //        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //        |T|S|       symbol list         |
            //        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //    chunk type (T):  1 bit A one identifies this as a status vector
            //                chunk.
            //    symbol size (S):  1 bit A zero means this vector contains only
            //                "packet received" (1) and "packet not received" (0)
            //                symbols.  This means we can compress each symbol to just
            //                one bit, 14 in total.  A one means this vector contains
            //                the normal 2-bit symbols, 7 in total.
            //    symbol list:  14 bits A list of packet status symbols, 7 or 14 in
            //                total.
            PacketChunk::Vector(v) => {
                let mut x: u16 = 1 << 15;
                match v {
                    Symbol::Single(n) => {
                        assert!(*n <= 16384);
                        x |= *n;
                    }
                    Symbol::Double(n) => {
                        assert!(*n <= 16384);
                        x |= 1 << 14;
                        x |= *n;
                    }
                }
                x
            }
        };
        (&mut buf[..2]).copy_from_slice(&x.to_be_bytes());
    }

    fn max_possible_status_count(&self) -> usize {
        match self {
            PacketChunk::Run(_, n) => *n as usize,
            PacketChunk::Vector(v) => match v {
                Symbol::Single(_) => 14,
                Symbol::Double(_) => 7,
            },
        }
    }
}

impl Delta {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        match self {
            Delta::Small(v) => {
                buf[0] = *v;
                1
            }
            Delta::Large(v) => {
                (&mut buf[..2]).copy_from_slice(&v.to_be_bytes());
                2
            }
        }
    }

    fn byte_len(&self) -> usize {
        match self {
            Delta::Small(_) => 1,
            Delta::Large(_) => 2,
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

impl<'a> TryFrom<&'a [u8]> for Twcc {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 20 {
            return Err("Less than 20 bytes for start of Twcc");
        }

        let sender_ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]).into();
        let base_seq = u16::from_be_bytes([buf[8], buf[9]]);
        let status_count = u16::from_be_bytes([buf[10], buf[11]]);
        let reference_time = u32::from_be_bytes([0, buf[12], buf[13], buf[14]]);
        let feedback_count = buf[15];

        let mut twcc = Twcc {
            sender_ssrc,
            ssrc,
            base_seq,
            status_count,
            reference_time,
            feedback_count,
            chunks: vec![],
            delta: vec![],
        };

        let mut todo = status_count as isize;
        let mut buf = &buf[16..];
        loop {
            let chunk: PacketChunk = buf.try_into()?;

            todo -= chunk.max_possible_status_count() as isize;

            twcc.chunks.push(chunk);
            buf = &buf[2..];

            if todo <= 0 {
                break;
            }
        }

        if twcc.chunks.is_empty() {
            return Ok(twcc);
        }

        fn read_delta_small(
            buf: &[u8],
            n: usize,
        ) -> Result<impl Iterator<Item = Delta> + '_, &'static str> {
            if buf.len() < n {
                return Err("Not enough buf for small deltas");
            }
            Ok((0..n).map(|i| Delta::Small(buf[i])))
        }

        fn read_delta_large(
            buf: &[u8],
            n: usize,
        ) -> Result<impl Iterator<Item = Delta> + '_, &'static str> {
            if buf.len() < n * 2 {
                return Err("Not enough buf for large deltas");
            }
            Ok((0..(n * 2))
                .step_by(2)
                .map(|i| Delta::Large(i16::from_be_bytes([buf[i], buf[i + 1]]))))
        }

        for c in &twcc.chunks {
            match c {
                PacketChunk::Run(PacketStatus::ReceivedSmallDelta, n) => {
                    let n = *n as usize;
                    twcc.delta.extend(read_delta_small(buf, n)?);
                    buf = &buf[n..];
                }
                PacketChunk::Run(PacketStatus::ReceivedLargeOrNegativeDelta, n) => {
                    let n = *n as usize;
                    twcc.delta.extend(read_delta_large(buf, n)?);
                    buf = &buf[n..];
                }
                PacketChunk::Vector(Symbol::Single(v)) => {
                    let n = v.count_ones() as usize;
                    twcc.delta.extend(read_delta_small(buf, n)?);
                    buf = &buf[n..];
                }
                PacketChunk::Vector(Symbol::Double(v)) => {
                    for n in (0..12).step_by(2) {
                        let x = (*v >> (12 - n)) & 0b11;
                        match PacketStatus::from(x as u8) {
                            PacketStatus::ReceivedSmallDelta => {
                                twcc.delta.extend(read_delta_small(buf, 1)?);
                                buf = &buf[1..];
                            }
                            PacketStatus::ReceivedLargeOrNegativeDelta => {
                                twcc.delta.extend(read_delta_large(buf, 1)?);
                                buf = &buf[2..];
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(twcc)
    }
}

impl<'a> TryFrom<&'a [u8]> for PacketChunk {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 2 {
            return Err("Less than 2 bytes for PacketChunk");
        }

        let x = u16::from_be_bytes([buf[0], buf[1]]);

        let is_vec = (x & 0b1000_0000_0000_0000) > 0;

        let p = if is_vec {
            let is_double = (x & 0b0100_0000_0000_0000) > 0;
            let n = x & 0b0011_1111_1111_1111;
            if is_double {
                PacketChunk::Vector(Symbol::Double(n))
            } else {
                PacketChunk::Vector(Symbol::Single(n))
            }
        } else {
            let s: PacketStatus = ((x >> 13) as u8).into();
            let n = x & 0b0001_1111_1111_1111;
            PacketChunk::Run(s, n)
        };

        Ok(p)
    }
}

// pub enum PacketChunk {
//     Run(PacketStatus, u16), // 13 bit repeat
//     Vector(Symbol),
// }

// Below is a clarification of the RFC draft from an email exchange with Erik Språng (one of the authors).
//
// > I'm trying to implement the draft spec
// > https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01
// > I found a number of errors/inconsistencies in the RFC, and wonder who I should address this to.
// > I think the RFC could benefit from another revision.
// >
// > There are three problems listed below.
// >
// > 1. There's a contradiction between section 3.1.1 and the example in 3.1.3. First the RFC tells
// > me 11 is Reserved, later it shows an example using 11 saying it is a run of packets received w/o
// > recv delta. Which one is right?
// >
// > Section 3.1.1
// > ...
// > The status of a packet is described using a 2-bit symbol:
// > ...
// > 11 [Reserved]
// >
// > Section 3.1.3
// > ...
// > Example 2:
// >
// >       0                   1
// >       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// >      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// >      |0|1 1|0 0 0 0 0 0 0 0 1 1 0 0 0|
// >      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// >
// >
// >   This is a run of the "packet received, w/o recv delta" status of
// >   length 24.
//
// I believe this example is in error. Packets without receive deltas was a proposal for the v1
// protocol but was dropped iirc. Note that there is a newer header extension available, which
// when negotiated allows send-side control over when feedback is generated  - and that provides
// the option to omit all receive deltas from the feedback.
//
// > 2. In section 3.1.4 when using a 1-bit vector to indicate packet received or not received,
// > there's a contradiction between the the definition and the example. The definition says
// > "packet received" (0) and "packet not received" (1), while the example is the opposite way
// > around: 0 is packet not received. Which way around is it?
// >
// > symbol size (S):  1 bit A zero means this vector contains only
// >               "packet received" (0) and "packet not received" (1)
// >               symbols.  This means we can compress each symbol to just
// >               one bit, 14 in total.  A one means this vector contains
// >               the normal 2-bit symbols, 7 in total.
// > ...
// > Example 1:
// >
// >        0                   1
// >        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// >       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// >       |1|0|0 1 1 1 1 1 0 0 0 1 1 1 0 0|
// >       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// >
// >   This chunk contains, in order:
// >
// >      1x "packet not received"
// >
// >      5x "packet received"
//
// I believe the definition is wrong in this case. The intent is to just truncate the 2-bit values:
//
// 3.1.1.  Packet Status Symbols
//
//    The status of a packet is described using a 2-bit symbol:
//
//       00 Packet not received
//
//       01 Packet received, small delta
//
// So (0) for not received and (1) for received, small delta.
// This also matches what the libwebrtc source code does.
//
// > 3. In section 3.1.4 when using a 1-bit vector, the RFC doesn't say what a "packet received" in that
// > vector should be accompanied by in receive delta size. Is it an 8 bit delta or 16 bit
// > delta per "packet received"?
//
// Same as the question above, this is a truncation to (0) for not received and (1) for
// received, small delta.

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;

    #[test]
    fn register_write_parse_small_delta() {
        let mut reg = TwccRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));
        reg.update_seq(11.into(), now + Duration::from_millis(12));
        reg.update_seq(12.into(), now + Duration::from_millis(23));
        reg.update_seq(13.into(), now + Duration::from_millis(43));

        let report = reg.build_report(1000).unwrap();
        let mut buf = vec![0_u8; 1500];
        let n = report.write_to(&mut buf[..]);
        buf.truncate(n);

        let header: RtcpHeader = (&buf[..]).try_into().unwrap();
        let parsed: Twcc = (&buf[4..]).try_into().unwrap();

        assert_eq!(header, report.header());
        assert_eq!(parsed, report);
    }

    #[test]
    fn register_write_parse_small_delta_missing() {
        let mut reg = TwccRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));
        reg.update_seq(11.into(), now + Duration::from_millis(12));
        reg.update_seq(12.into(), now + Duration::from_millis(23));
        // 13 is not there
        reg.update_seq(14.into(), now + Duration::from_millis(43));

        let report = reg.build_report(1000).unwrap();
        let mut buf = vec![0_u8; 1500];
        let n = report.write_to(&mut buf[..]);
        buf.truncate(n);

        let header: RtcpHeader = (&buf[..]).try_into().unwrap();
        let parsed: Twcc = (&buf[4..]).try_into().unwrap();

        println!("{:?}", report);

        assert_eq!(header, report.header());
        assert_eq!(parsed, report);
    }

    #[test]
    fn register_write_parse_large_delta() {
        let mut reg = TwccRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));
        reg.update_seq(11.into(), now + Duration::from_millis(70));
        reg.update_seq(12.into(), now + Duration::from_millis(140));
        reg.update_seq(13.into(), now + Duration::from_millis(210));

        let report = reg.build_report(1000).unwrap();
        let mut buf = vec![0_u8; 1500];
        let n = report.write_to(&mut buf[..]);
        buf.truncate(n);

        let header: RtcpHeader = (&buf[..]).try_into().unwrap();
        let parsed: Twcc = (&buf[4..]).try_into().unwrap();

        assert_eq!(header, report.header());
        assert_eq!(parsed, report);
    }

    #[test]
    fn register_write_parse_mixed_delta() {
        let mut reg = TwccRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));
        reg.update_seq(11.into(), now + Duration::from_millis(12));
        reg.update_seq(12.into(), now + Duration::from_millis(140));
        reg.update_seq(13.into(), now + Duration::from_millis(152));

        let report = reg.build_report(1000).unwrap();
        let mut buf = vec![0_u8; 1500];
        let n = report.write_to(&mut buf[..]);
        buf.truncate(n);

        let header: RtcpHeader = (&buf[..]).try_into().unwrap();
        let parsed: Twcc = (&buf[4..]).try_into().unwrap();

        assert_eq!(header, report.header());
        assert_eq!(parsed, report);
    }

    #[test]
    fn too_big_time_gap_requires_two_reports() {
        let mut reg = TwccRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));
        reg.update_seq(11.into(), now + Duration::from_millis(12));
        reg.update_seq(12.into(), now + Duration::from_millis(9000));

        let _ = reg.build_report(1000).unwrap();
        let report2 = reg.build_report(1000).unwrap();

        // 9000 milliseconds is not possible to set as exact reference time which
        // is in multiples of 64ms. 9000/64 = 140.625.
        assert_eq!(report2.reference_time, 140);

        // 140 * 64 = 8960
        // So the first offset must be 40ms, i.e. 40_000us / 250us = 160
        assert_eq!(report2.delta[0], Delta::Small(160));
    }

    #[test]
    fn report_padded_to_even_word() {
        let mut reg = TwccRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));

        let report = reg.build_report(1000).unwrap();
        let mut buf = vec![0_u8; 1500];
        let n = report.write_to(&mut buf[..]);

        assert!(n % 4 == 0);
    }

    #[test]
    fn report_truncated_to_max_byte_size() {
        let mut reg = TwccRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));
        reg.update_seq(11.into(), now + Duration::from_millis(12));
        reg.update_seq(12.into(), now + Duration::from_millis(140));
        reg.update_seq(13.into(), now + Duration::from_millis(152));

        let report = reg.build_report(28).unwrap();

        assert_eq!(report.status_count, 1);
        assert_eq!(
            report.chunks,
            vec![PacketChunk::Vector(Symbol::Double(0b01 << 12))]
        );
        assert_eq!(report.delta, vec![Delta::Small(0)]);
    }

    #[test]
    fn truncated_counts_gaps_correctly() {
        let mut reg = TwccRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));
        // gap
        reg.update_seq(13.into(), now + Duration::from_millis(12));
        reg.update_seq(14.into(), now + Duration::from_millis(140));
        reg.update_seq(15.into(), now + Duration::from_millis(152));

        let report = reg.build_report(32).unwrap();

        assert_eq!(report.status_count, 4);
        assert_eq!(
            report.chunks,
            vec![PacketChunk::Vector(Symbol::Double(0b01_00_00_01_00_00_00))]
        );
        assert_eq!(report.delta, vec![Delta::Small(0), Delta::Small(48)]);
    }

    #[test]
    fn run_max_is_8192() {
        let mut reg = TwccRegister::new(100);

        let now = Instant::now();

        reg.update_seq(0.into(), now + Duration::from_millis(0));
        reg.update_seq(8194.into(), now + Duration::from_millis(10));

        let report = reg.build_report(1000).unwrap();

        assert_eq!(report.status_count, 8195);
        assert_eq!(
            report.chunks,
            vec![
                PacketChunk::Run(PacketStatus::ReceivedSmallDelta, 1),
                PacketChunk::Run(PacketStatus::NotReceived, 8192),
                PacketChunk::Vector(Symbol::Single(4096))
            ]
        );
    }

    #[test]
    fn negative_deltas() {
        let mut reg = TwccRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(12));
        reg.update_seq(11.into(), now + Duration::from_millis(0));
        reg.update_seq(12.into(), now + Duration::from_millis(23));

        let report = reg.build_report(1000).unwrap();

        assert_eq!(report.status_count, 3);
        assert_eq!(
            report.chunks,
            vec![PacketChunk::Vector(Symbol::Double(6400))]
        );
        assert_eq!(
            report.delta,
            vec![Delta::Small(0), Delta::Large(-48), Delta::Small(92)]
        );
    }
}
