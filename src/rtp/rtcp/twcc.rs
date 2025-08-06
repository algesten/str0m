use std::collections::vec_deque;
use std::collections::VecDeque;
use std::fmt;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use super::{extend_u16, FeedbackMessageType, RtcpHeader, RtcpPacket};
use super::{RtcpType, SeqNo, Ssrc, TransportType};

/// Transport Wide Congestion Control.
///
/// Sent in response to every RTP packet, but does ranges of packets to respond to.
#[derive(Clone, PartialEq, Eq)]
pub struct Twcc {
    /// Sender of this feedback. Mostly irrelevant, but part of RTCP packets.
    pub sender_ssrc: Ssrc,
    /// The SSRC this report is for.
    pub ssrc: Ssrc,
    /// Start sequence number.
    pub base_seq: u16,
    /// Number of reported statuses.
    pub status_count: u16,
    /// Clock time this report was produced. Used for RTT measurement.
    pub reference_time: u32, // 24 bit
    /// Increasing counter for each TWCC. For deduping.
    pub feedback_count: u8, // counter for each Twcc
    /// Ranges received.
    pub chunks: VecDeque<PacketChunk>,
    /// Delta times for the ranges received.
    pub delta: VecDeque<Delta>,
}

impl Twcc {
    fn chunks_byte_len(&self) -> usize {
        self.chunks.len() * 2
    }

    fn delta_byte_len(&self) -> usize {
        self.delta.iter().map(|d| d.byte_len()).sum()
    }

    /// Iterate over the reported sequences.
    pub fn into_iter(self, time_zero: Instant, extend_from: SeqNo) -> TwccIter {
        let millis = self.reference_time as u64 * 64;
        let time_base = time_zero + Duration::from_millis(millis);
        let base_seq = extend_u16(Some(*extend_from), self.base_seq);
        let last_seq = base_seq + self.status_count as u64;

        TwccIter {
            base_seq,
            last_seq,
            time_base,
            index: 0,
            twcc: self,
        }
    }
}

pub struct TwccIter {
    base_seq: u64,
    last_seq: u64,
    time_base: Instant,
    index: usize,
    twcc: Twcc,
}

impl Iterator for TwccIter {
    type Item = (SeqNo, PacketStatus, Option<Instant>);

    fn next(&mut self) -> Option<Self::Item> {
        let seq: SeqNo = (self.base_seq + self.index as u64).into();

        if *seq == self.last_seq {
            return None;
        }

        let head = self.twcc.chunks.front()?;

        let (status, amount) = match head {
            PacketChunk::Run(s, n) => {
                use PacketStatus::*;
                let status = match s {
                    NotReceived | Unknown => NotReceived,
                    ReceivedSmallDelta => ReceivedSmallDelta,
                    PacketStatus::ReceivedLargeOrNegativeDelta => ReceivedLargeOrNegativeDelta,
                };
                (status, *n)
            }
            PacketChunk::VectorSingle(v, n) => {
                let status = if 1 << (13 - self.index) & v > 0 {
                    PacketStatus::ReceivedSmallDelta
                } else {
                    PacketStatus::NotReceived
                };
                (status, *n)
            }
            PacketChunk::VectorDouble(v, n) => {
                let e = ((v >> (12 - self.index * 2)) & 0b11) as u8;
                let status = PacketStatus::from(e);
                (status, *n)
            }
        };

        let instant = match status {
            PacketStatus::NotReceived => None,
            PacketStatus::ReceivedSmallDelta => match self.twcc.delta.pop_front()? {
                Delta::Small(v) => Some(self.time_base + Duration::from_micros(250 * v as u64)),
                Delta::Large(_) => panic!("Incorrect large delta size"),
            },
            PacketStatus::ReceivedLargeOrNegativeDelta => match self.twcc.delta.pop_front()? {
                Delta::Small(_) => panic!("Incorrect small delta size"),
                Delta::Large(v) => {
                    let dur = Duration::from_micros(250 * v.unsigned_abs() as u64);
                    Some(if v < 0 {
                        self.time_base.checked_sub(dur).unwrap()
                    } else {
                        self.time_base + dur
                    })
                }
            },
            _ => unreachable!(),
        };

        if let Some(new_timebase) = instant {
            self.time_base = new_timebase;
        }

        self.index += 1;
        if self.index == amount as usize {
            self.twcc.chunks.pop_front();
            self.base_seq = *seq + 1;
            self.index = 0;
        }

        Some((seq, status, instant))
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

        let mut total = {
            let buf = &mut buf[..];

            self.header().write_to(buf);
            buf[4..8].copy_from_slice(&self.sender_ssrc.to_be_bytes());
            buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

            buf[12..14].copy_from_slice(&self.base_seq.to_be_bytes());
            buf[14..16].copy_from_slice(&self.status_count.to_be_bytes());

            let ref_time = self.reference_time.to_be_bytes();
            buf[16..19].copy_from_slice(&ref_time[1..4]);
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

            len_start - buf.len()
        };

        let pad = 4 - total % 4;
        if pad < 4 {
            for i in 0..pad {
                buf[total + i] = 0;
            }
            buf[total + pad - 1] = pad as u8;

            total += pad;
            // Toggle padding bit
            buf[0] |= 0b00_1_00000;
        }

        total
    }
}

#[derive(Debug)]
pub struct TwccRecvRegister {
    // How many packets to keep when they are reported. This is to handle packets arriving out
    // of order and where two consecutive calls to `build_report` needs to go "backwards" in
    // base_seq.
    keep_reported: usize,

    /// Queue of packets to form Twcc reports of.
    ///
    /// Once the queue has some content, we will always keep at least one entry to "remember" for the
    /// next report.
    queue: VecDeque<Receipt>,

    /// Index into queue from where we start reporting on next build_report().
    report_from: usize,

    /// Interims built in this for every build_report.
    interims: VecDeque<ChunkInterim>,

    /// The point in time we consider 0. All reported values are offset from this. Set to first
    /// unreported packet in first `build_reported`.
    ///
    // https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01#page-5
    // reference time: 24 bits Signed integer indicating an absolute
    // reference time in some (unknown) time base chosen by the
    // sender of the feedback packets.
    time_start: Option<Instant>,

    /// Counter that increases by one for each report generated.
    generated_reports: u64,

    /// Data to calculate received loss.
    receive_window: ReceiveWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Receipt {
    seq: SeqNo,
    time: Instant,
}

impl TwccRecvRegister {
    pub fn new(keep_reported: usize) -> Self {
        TwccRecvRegister {
            keep_reported,
            queue: VecDeque::new(),
            report_from: 0,
            interims: VecDeque::new(),
            time_start: None,
            generated_reports: 0,
            receive_window: ReceiveWindow::default(),
        }
    }

    pub fn max_seq(&self) -> SeqNo {
        // The highest seq must be the last since update_seq inserts values
        // using a binary search.
        self.queue.back().map(|r| r.seq).unwrap_or_else(|| 0.into())
    }

    pub fn update_seq(&mut self, seq: SeqNo, time: Instant) {
        self.receive_window.record_seq(seq);

        match self.queue.binary_search_by_key(&seq, |r| r.seq) {
            Ok(_) => {
                // Exact same SeqNo found. This is an error where the sender potentially
                // used the same twcc sequence number for two packets. Let's ignore it.
            }
            Err(idx) => {
                if let Some(time_start) = self.time_start {
                    // If time goes back more than 8192 millis from the time point we've
                    // chosen as our 0, we can't represent that in the report. Let's just
                    // forget about it and hope for the best.
                    if time_start - time >= Duration::from_millis(8192) {
                        return;
                    }
                }

                self.queue.insert(idx, Receipt { seq, time });

                if idx < self.report_from {
                    self.report_from = idx;
                }
            }
        }
    }

    pub fn build_report(&mut self, max_byte_size: usize) -> Option<Twcc> {
        if max_byte_size > 10_000 {
            warn!("Refuse to build too large Twcc report");
            return None;
        }

        // First unreported is the self.time_start relative offset of the next Twcc.
        let first = self.queue.get(self.report_from);
        let first = first?;

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
            feedback_count: self.generated_reports as u8,
            base_seq: *base_seq as u16,
            reference_time,
            status_count: 0,
            chunks: VecDeque::new(),
            delta: VecDeque::new(),
        };

        // Because reference time is in steps of 64ms, the first reported packet might have an
        // offset (packet time resolution is 250us). This base_time is calculated backwards from
        // reference time so that we can offset all packets from the "truncated" 64ms steps.
        // The RFC says:
        // The first recv delta in this packet is relative to the reference time.
        let base_time = time_start + Duration::from_micros(reference_time as u64 * 64_000);

        // The ChunkInterim are helpers structures that hold the deltas between
        // the registered receptions.
        build_interims(
            &self.queue,
            self.report_from,
            base_seq,
            base_time,
            &mut self.interims,
        );
        let interims = &mut self.interims;

        // 20 bytes is the size of the fixed fields in Twcc.
        let mut bytes_left = max_byte_size - 20;

        while !interims.is_empty() {
            // 2 chunk + 2 large delta + 3 padding
            const MIN_RUN_SIZE: usize = 2 + 2 + 3;

            if bytes_left < MIN_RUN_SIZE {
                break;
            }

            // Chose the packet chunk type that can fit the most interims.
            let (mut chunk, max) = {
                let first_status = interims.front().expect("at least one interim").status();

                let c_run = PacketChunk::Run(first_status, 0);
                let c_single = PacketChunk::VectorSingle(0, 0);
                let c_double = PacketChunk::VectorDouble(0, 0);

                let max_run = c_run.append_max(interims.iter());
                let max_single = c_single.append_max(interims.iter());
                let max_double = c_double.append_max(interims.iter());

                let max = max_run.max(max_single).max(max_double);

                // 2 chunk + 14 small delta + 3 padding
                const MAX_SINGLE_SIZE: usize = 2 + 14 + 3;
                // 2 chunk + 7 large delta  + 3 padding
                const MAX_DOUBLE_SIZE: usize = 2 + 14 + 3;

                if max == max_run {
                    (c_run, max_run)
                } else if max == max_single && bytes_left >= MAX_SINGLE_SIZE {
                    (c_single, max_single)
                } else if max == max_double && bytes_left >= MAX_DOUBLE_SIZE {
                    (c_double, max_double)
                } else {
                    // fallback, since we can always do runs.
                    (c_run, max_run)
                }
            };

            // we should _definitely_ be able to fit this many reported.
            let mut todo = max;

            loop {
                if bytes_left < MIN_RUN_SIZE {
                    break;
                }

                if todo == 0 {
                    break;
                }

                let i = match interims.front_mut() {
                    Some(v) => v,
                    None => break,
                };

                let appended = chunk.append(i);
                assert!(appended > 0);
                todo -= appended;
                twcc.status_count += appended;

                if i.consume(appended) {
                    // it was fully consumed.
                    if matches!(i, ChunkInterim::Received(_, _)) {
                        self.report_from += 1;
                    }

                    if let Some(delta) = i.delta() {
                        twcc.delta.push_back(delta);
                        bytes_left -= delta.byte_len();
                    }

                    // move on to next interim
                    interims.pop_front();
                } else {
                    // not fully consumed, then we must have run out of space in the chunk.
                    assert!(todo == 0);
                }
            }

            let free = chunk.free();
            if chunk.must_be_full() && free > 0 {
                // this must be at the end where we can shift in missing
                assert!(interims.is_empty());
                chunk.append(&ChunkInterim::Missing(free));
            }

            twcc.chunks.push_back(chunk);
            bytes_left -= 2;
        }

        // libWebRTC demands at least one chunk, or it will warn with
        // "Buffer too small (16 bytes) to fit a FeedbackPacket. Minimum size = 18"
        // (18 bytes here is not including the RTCP header).
        if twcc.chunks.is_empty() {
            return None;
        }

        self.generated_reports += 1;

        // clean up
        if self.report_from > self.keep_reported {
            let to_remove = self.report_from - self.keep_reported;
            self.queue.drain(..to_remove);
            self.report_from -= to_remove;
        }

        Some(twcc)
    }

    pub fn has_unreported(&self) -> bool {
        self.queue.len() > self.report_from
    }

    /// Calculate the fraction of lost packets since the last call.
    ///
    /// To get periodic stats call this method at fixed intervals.
    pub fn loss(&mut self) -> Option<f32> {
        // Based on the algorithm described in
        // [RFC 3550 Appendix A](https://www.rfc-editor.org/rfc/rfc3550#appendix-A.3), but instead
        // of applying it to an individual RTP stream it's applied to the whole session using TWCC
        // sequence numbers rather than RTP sequence numbers.
        let max_seq = self.receive_window.max_seq?;
        let base_seq = self.receive_window.base_seq?;
        let expected = *max_seq - *base_seq + 1_u64;

        let expected_interval = expected - self.receive_window.expected_prior;
        self.receive_window.expected_prior = expected;

        let received_interval = self.receive_window.received - self.receive_window.received_prior;
        self.receive_window.received_prior = self.receive_window.received;

        let lost_interval = expected_interval.saturating_sub(received_interval);

        (expected_interval != 0).then_some(lost_interval as f32 / expected_interval as f32)
    }
}

/// Interims are deltas between `Receiption` which is an intermediary format before
/// we populate the Twcc report.
fn build_interims(
    queue: &VecDeque<Receipt>,
    report_from: usize,
    base_seq: SeqNo,
    base_time: Instant,
    interims: &mut VecDeque<ChunkInterim>,
) {
    interims.clear();
    let report_from = queue.iter().skip(report_from);

    let mut prev = (base_seq, base_time);

    for r in report_from {
        let diff_seq = *r.seq - *prev.0;

        if diff_seq > 1 {
            let mut todo = diff_seq - 1;
            while todo > 0 {
                // max 2^13 run length in each missing chunk
                let n = todo.min(8192);
                interims.push_back(ChunkInterim::Missing(n as u16));
                todo -= n;
            }
        }

        let diff_time = if r.time < prev.1 {
            // negative
            let dur = prev.1 - r.time;
            -(dur.as_micros() as i64)
        } else {
            let dur = r.time - prev.1;
            dur.as_micros() as i64
        };

        let (status, time) = if diff_time < -8_192_000 || diff_time > 8_191_750 {
            // This is too large to be representable in deltas.
            // Abort, make a report of what we got, and start anew.
            break;
        } else if diff_time < 0 || diff_time > 63_750 {
            let t = diff_time / 250;
            assert!(t >= -32_768 && t <= 32_767);
            (PacketStatus::ReceivedLargeOrNegativeDelta, t as i16)
        } else {
            let t = diff_time / 250;
            assert!(t >= 0 && t <= 255);
            (PacketStatus::ReceivedSmallDelta, t as i16)
        };

        interims.push_back(ChunkInterim::Received(status, time));
        prev = (r.seq, r.time);
    }
}

#[derive(Debug, Clone, Copy)]
enum ChunkInterim {
    Missing(u16), // max 2^13 (one run length)
    Received(PacketStatus, i16),
}

#[derive(Debug, Default)]
struct ReceiveWindow {
    /// The base seq num, set on the first receive.
    base_seq: Option<SeqNo>,

    /// The large seq num received.
    max_seq: Option<SeqNo>,

    /// The previous number of packets expected, used to calculate a delta for loss.
    expected_prior: u64,

    /// The total number of packets received
    received: u64,

    /// The previous number of packets received, used to calculate a delta for loss.
    received_prior: u64,
}

impl ReceiveWindow {
    fn record_seq(&mut self, seq: SeqNo) {
        if self.base_seq.is_none() {
            self.base_seq = Some(seq);
        }

        self.received += 1;
        self.max_seq = self.max_seq.max(Some(seq));
    }
}

impl ChunkInterim {
    fn status(&self) -> PacketStatus {
        match self {
            ChunkInterim::Missing(_) => PacketStatus::NotReceived,
            ChunkInterim::Received(s, _) => *s,
        }
    }

    fn delta(&self) -> Option<Delta> {
        match self {
            ChunkInterim::Missing(_) => None,
            ChunkInterim::Received(s, d) => match *s {
                PacketStatus::ReceivedSmallDelta => Some(Delta::Small(*d as u8)),
                PacketStatus::ReceivedLargeOrNegativeDelta => Some(Delta::Large(*d)),
                _ => unreachable!(),
            },
        }
    }

    fn consume(&mut self, n: u16) -> bool {
        match self {
            ChunkInterim::Missing(c) => {
                *c -= n;
                *c == 0
            }
            ChunkInterim::Received(_, _) => {
                assert!(n <= 1);
                n == 1
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketChunk {
    Run(PacketStatus, u16), // 13 bit repeat
    VectorSingle(u16, u16),
    VectorDouble(u16, u16),
}

impl PacketChunk {
    fn append_max<'a>(&self, iter: impl Iterator<Item = &'a ChunkInterim>) -> u16 {
        let mut to_fill = *self;

        let mut reached_end = true;

        for i in iter {
            if to_fill.free() == 0 {
                reached_end = false;
                break;
            }

            // The status is not possible to add in this chunk. This could be
            // a large delta in a single, or a mismatching run.
            if !to_fill.can_append_status(i.status()) {
                reached_end = false;
                break;
            }

            to_fill.append(i);
        }

        // As a special case, single/double must be completely filled. However if
        // we reached the end of the interims, we can shift in "missing" to make
        // them full.
        if to_fill.must_be_full() && to_fill.free() > 0 && !reached_end {
            return 0;
        }

        self.free() - to_fill.free()
    }

    fn append(&mut self, i: &ChunkInterim) -> u16 {
        use ChunkInterim::*;
        use PacketChunk::*;
        let free = self.free();
        match (self, i) {
            (Run(s, n), Missing(c)) => {
                if *s != PacketStatus::NotReceived {
                    return 0;
                }
                let max = free.min(*c);
                *n += max;
                max
            }
            (Run(s, n), Received(s2, _)) => {
                if *s != *s2 {
                    return 0;
                }
                let max = free.min(1);
                *n += max;
                max
            }
            (VectorSingle(n, f), Missing(c)) => {
                let max = free.min(*c);
                *n <<= max;
                *f += max;
                max
            }
            (VectorSingle(n, f), Received(s2, _)) => {
                if *s2 == PacketStatus::ReceivedLargeOrNegativeDelta {
                    return 0;
                }
                let max = free.min(1);
                if max == 1 {
                    *n <<= 1;
                    *n |= 1;
                    *f += 1;
                }
                max
            }
            (VectorDouble(n, f), Missing(c)) => {
                let max = free.min(*c);
                *n <<= max * 2;
                *f += max;
                max
            }
            (VectorDouble(n, f), Received(s2, _)) => {
                let max = free.min(1);
                if max == 1 {
                    *n <<= 2;
                    *n |= *s2 as u16;
                    *f += 1;
                }
                max
            }
        }
    }

    fn must_be_full(&self) -> bool {
        match self {
            PacketChunk::Run(_, _) => false,
            PacketChunk::VectorSingle(_, _) => true,
            PacketChunk::VectorDouble(_, _) => true,
        }
    }

    fn free(&self) -> u16 {
        match self {
            PacketChunk::Run(_, n) => 8192 - *n,
            PacketChunk::VectorSingle(_, filled) => 14 - *filled,
            PacketChunk::VectorDouble(_, filled) => 7 - *filled,
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
            PacketChunk::VectorSingle(n, fill) => {
                assert!(*fill == 14);
                let mut x: u16 = 1 << 15;
                assert!(*n <= 16384);
                x |= *n;
                x
            }
            PacketChunk::VectorDouble(n, fill) => {
                assert!(*fill == 7);
                let mut x: u16 = 1 << 15;
                assert!(*n <= 16384);
                x |= 1 << 14;
                x |= *n;
                x
            }
        };
        buf[..2].copy_from_slice(&x.to_be_bytes());
    }

    fn max_possible_status_count(&self) -> usize {
        match self {
            PacketChunk::Run(_, n) => *n as usize,
            PacketChunk::VectorSingle(_, _) => 14,
            PacketChunk::VectorDouble(_, _) => 7,
        }
    }

    fn can_append_status(&self, status: PacketStatus) -> bool {
        match self {
            PacketChunk::Run(s, _) => *s == status,
            PacketChunk::VectorSingle(_, _) => status != PacketStatus::ReceivedLargeOrNegativeDelta,
            PacketChunk::VectorDouble(_, _) => true,
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
                buf[..2].copy_from_slice(&v.to_be_bytes());
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
pub enum Delta {
    Small(u8),
    Large(i16),
}

impl From<PacketStatus> for u8 {
    fn from(val: PacketStatus) -> Self {
        val as usize as u8
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
        if buf.len() < 16 {
            return Err("Less than 16 bytes for start of Twcc");
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
            chunks: VecDeque::new(),
            delta: VecDeque::new(),
        };

        let mut todo = status_count as isize;
        let mut buf = &buf[16..];
        loop {
            if todo <= 0 {
                break;
            }

            let chunk: PacketChunk = buf.try_into()?;

            todo -= chunk.max_possible_status_count() as isize;

            twcc.chunks.push_back(chunk);
            buf = &buf[2..];
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
                PacketChunk::VectorSingle(v, _) => {
                    let n = v.count_ones() as usize;
                    twcc.delta.extend(read_delta_small(buf, n)?);
                    buf = &buf[n..];
                }
                PacketChunk::VectorDouble(v, _) => {
                    for n in (0..=12).step_by(2) {
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
                PacketChunk::VectorDouble(n, 7)
            } else {
                PacketChunk::VectorSingle(n, 14)
            }
        } else {
            let s: PacketStatus = ((x >> 13) as u8).into();
            let n = x & 0b0001_1111_1111_1111;
            PacketChunk::Run(s, n)
        };

        Ok(p)
    }
}

#[derive(Debug)]
pub struct TwccSendRegister {
    /// How many send records to keep.
    keep: usize,

    /// Circular buffer of send records.
    queue: VecDeque<TwccSendRecord>,

    /// 0 offset for remote time in Twcc structs.
    time_zero: Option<Instant>,

    /// Counter of invocations of apply_report. Used to identify
    /// which TwccSendRecord resulted from each invocation.
    apply_report_counter: u64,

    /// Last registered Twcc number.
    last_registered: SeqNo,
}

impl<'a> IntoIterator for &'a TwccSendRegister {
    type Item = &'a TwccSendRecord;
    type IntoIter = vec_deque::Iter<'a, TwccSendRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.queue.iter()
    }
}

/// Record for a send entry in twcc.
#[derive(Debug)]
pub struct TwccSendRecord {
    /// Twcc sequence number for a packet we sent.
    seq: SeqNo,

    /// The (local) time we sent the packet represented by seq.
    local_send_time: Instant,

    /// Size in bytes of the payload sent.
    size: u16,

    recv_report: Option<TwccRecvReport>,
}

impl TwccSendRecord {
    /// The twcc sequence number of the packet we sent.
    pub fn seq(&self) -> SeqNo {
        self.seq
    }

    /// The time we sent the packet.
    pub fn local_send_time(&self) -> Instant {
        self.local_send_time
    }

    /// The time we received this TWCC record. [`None`] if no feedback has been received yet.
    pub fn local_recv_time(&self) -> Option<Instant> {
        self.recv_report.as_ref().map(|r| r.local_recv_time)
    }

    pub fn size(&self) -> usize {
        self.size as usize
    }

    /// The time indicated by the remote side for when they received the packet.
    pub fn remote_recv_time(&self) -> Option<Instant> {
        self.recv_report.as_ref().and_then(|r| r.remote_recv_time)
    }

    /// The rtt time between sending the packet and receiving the twcc report response.
    pub fn rtt(&self) -> Option<Duration> {
        let recv_report = self.recv_report.as_ref()?;
        Some(recv_report.local_recv_time - self.local_send_time)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TwccRecvReport {
    ///  The (local) time we received confirmation the other side received the seq.
    local_recv_time: Instant,

    /// The remote time the other side received the seq.
    remote_recv_time: Option<Instant>,

    /// The invocation count of apply_report(). Used for filtering.
    apply_report_counter: u64,
}

impl TwccSendRegister {
    pub fn new(keep: usize) -> Self {
        TwccSendRegister {
            keep,
            queue: VecDeque::new(),
            time_zero: None,
            apply_report_counter: 0,
            last_registered: 0.into(),
        }
    }

    pub fn register_seq(&mut self, seq: SeqNo, now: Instant, size: usize) {
        self.last_registered = seq;
        self.queue.push_back(TwccSendRecord {
            seq,
            local_send_time: now,
            // In practice the max sizes is constrained by the MTU and will max out around 1200
            // bytes, hence this cast is fine.
            size: size as u16,
            // The recv report, derived from TWCC feedback later.
            recv_report: None,
        });
        while self.queue.len() > self.keep {
            self.queue.pop_front();
        }
    }

    /// Apply a TWCC RTCP report.
    ///
    /// Returns iterator over [`TwccSendRecord`]s included in the given [`Twcc`]
    /// except for ones that was already acked and returned before.
    pub fn apply_report(
        &mut self,
        twcc: Twcc,
        now: Instant,
    ) -> Option<impl Iterator<Item = &TwccSendRecord>> {
        if self.time_zero.is_none() {
            self.time_zero = Some(now);
        }

        self.apply_report_counter += 1;
        let apply_report_counter = self.apply_report_counter;

        let time_zero = self.time_zero.unwrap();
        let head_seq = self.queue.front().map(|r| r.seq)?;

        let mut iter = twcc
            .into_iter(time_zero, self.last_registered)
            .skip_while(|(seq, _, _)| seq < &head_seq);
        let (first_seq_no, _, first_instant) = iter.next()?;

        let mut iter2 = self.queue.iter_mut().skip_while(|r| *r.seq < *first_seq_no);
        let first_record = iter2.next()?;

        fn update(
            now: Instant,
            r: &mut TwccSendRecord,
            seq: SeqNo,
            remote_recv_time: Option<Instant>,
            apply_report_counter: u64,
        ) -> bool {
            if r.seq != seq {
                return false;
            }

            let apply_report_counter = if let Some(rr) = r.recv_report {
                // This packed was already acked and handled before so carry
                // over previous apply_report_counter, so it won't be included
                // in the current apply_report() call result.
                rr.remote_recv_time
                    .map(|_| rr.apply_report_counter)
                    .unwrap_or_else(|| apply_report_counter)
            } else {
                apply_report_counter
            };

            // Carry over remote recv time if this packet was acked before.
            let remote_recv_time = r.remote_recv_time().or(remote_recv_time);
            let recv_report = TwccRecvReport {
                local_recv_time: now,
                remote_recv_time,
                apply_report_counter,
            };
            r.recv_report = Some(recv_report);

            true
        }

        if first_record.seq != first_seq_no {
            // Old report for which we no longer have any send records.
            return None;
        }

        let mut problematic_seq = None;

        if !update(
            now,
            first_record,
            first_seq_no,
            first_instant,
            apply_report_counter,
        ) {
            problematic_seq = Some((first_record.seq, first_seq_no));
        }

        let mut last_seq_no = first_seq_no;
        for ((seq, _, instant), record) in iter.zip(iter2) {
            if problematic_seq.is_some() {
                break;
            }

            if !update(now, record, seq, instant, apply_report_counter) {
                problematic_seq = Some((record.seq, seq));
            }
            last_seq_no = seq;
        }

        if let Some((record_seq, report_seq)) = problematic_seq {
            let queue_tail: Vec<_> = self.queue.iter().rev().take(100).collect();
            panic!(
                "Unexpected TWCC sequence when applying TWCC report. \
                    Send Record Seq({record_seq}) does not match Report Seq({report_seq}).\
                    \nLast 100 entires in queue: {queue_tail:?}."
            );
        }

        let first_index = self
            .queue
            .binary_search_by_key(&first_seq_no, |r| r.seq)
            .expect("first_seq_no to be registered");

        let range = first_seq_no..=last_seq_no;

        Some(
            TwccSendRecordsIter {
                range: range.clone(),
                index: first_index,
                current: first_seq_no,
                queue: &self.queue,
            }
            // We only want the records that were registered in this invocation of
            // apply_report_counter(). This is to not double count in the BWE,
            // which is the consumer of this returned iterator.
            .filter(move |s| {
                s.recv_report
                    .map(|r| r.apply_report_counter == apply_report_counter)
                    .unwrap_or_default()
            }),
        )
    }

    /// Calculate the egress loss for given time window.
    ///
    /// **Note:** The register only keeps a limited number of records and using `duration` values
    /// larger than ~1-2 seconds is liable to be inaccurate since some packets sent might have already
    /// been evicted from the register.
    pub fn loss(&self, duration: Duration, now: Instant) -> Option<f32> {
        // Consider only packets in the span specified by the caller
        let lower_bound = now - duration;

        let packets = self
            .queue
            .iter()
            .rev()
            // If there's ingress loss but no egress loss, there's a chance the TWCC reports
            // themselves are lost. In this case considering packets that haven't been reported as
            // lost will incorrectly conclude that there is in fact egress loss.
            .filter(|s| s.recv_report.is_some())
            .take_while(|s| s.local_send_time >= lower_bound);

        let (total, lost) = packets.fold((0, 0), |(total, lost), s| {
            let was_lost = s
                .recv_report
                .as_ref()
                .map(|rr| rr.remote_recv_time.is_none())
                .unwrap_or(true);

            (total + 1, lost + u64::from(was_lost))
        });

        if total == 0 {
            return None;
        }

        Some((lost as f32) / (total as f32))
    }

    /// Calculate the RTT for the most recently reported packet.
    pub fn rtt(&self) -> Option<Duration> {
        self.queue.iter().rev().find_map(|s| s.rtt())
    }
}

#[derive()]
struct TwccSendRecordsIter<'a> {
    range: RangeInclusive<SeqNo>,
    current: SeqNo,
    index: usize,
    queue: &'a VecDeque<TwccSendRecord>,
}

impl<'a> Iterator for TwccSendRecordsIter<'a> {
    type Item = &'a TwccSendRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current > *self.range.end() || self.current < *self.range.start() {
            return None;
        }

        let item = &self.queue[self.index];
        assert!(self.current == item.seq);
        self.current.inc();
        self.index += 1;

        Some(item)
    }
}

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

impl fmt::Debug for Twcc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Twcc")
            .field("sender_ssrc", &self.sender_ssrc)
            .field("ssrc", &self.ssrc)
            .field("base_seq", &self.base_seq)
            .field("status_count", &self.status_count)
            .field("reference_time", &self.reference_time)
            .field("feedback_count", &self.feedback_count)
            .field("chunks", &self.chunks)
            .field("delta", &self.delta.len())
            .finish()
    }
}

#[allow(clippy::assign_op_pattern)]
#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;

    use Delta::*;
    use PacketChunk::*;
    use PacketStatus::*;

    #[test]
    fn register_write_parse_small_delta() {
        let mut reg = TwccRecvRegister::new(100);

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
        let mut reg = TwccRecvRegister::new(100);

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

        assert_eq!(header, report.header());
        assert_eq!(parsed, report);
    }

    #[test]
    fn register_write_parse_large_delta() {
        let mut reg = TwccRecvRegister::new(100);

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
        let mut reg = TwccRecvRegister::new(100);

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
        let mut reg = TwccRecvRegister::new(100);

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
        assert_eq!(report2.delta[0], Small(160));
    }

    #[test]
    fn report_padded_to_even_word() {
        let mut reg = TwccRecvRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));

        let report = reg.build_report(1000).unwrap();
        let mut buf = vec![0_u8; 1500];
        let n = report.write_to(&mut buf[..]);

        assert!(n % 4 == 0);
    }

    #[test]
    fn report_truncated_to_max_byte_size() {
        let mut reg = TwccRecvRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));
        reg.update_seq(11.into(), now + Duration::from_millis(12));
        reg.update_seq(12.into(), now + Duration::from_millis(140));
        reg.update_seq(13.into(), now + Duration::from_millis(152));

        let report = reg.build_report(28).unwrap();

        assert_eq!(report.status_count, 2);
        assert_eq!(report.chunks, vec![Run(ReceivedSmallDelta, 2)]);
        assert_eq!(report.delta, vec![Small(0), Small(48)]);

        let report = reg.build_report(28).unwrap();

        assert_eq!(report.status_count, 2);
        assert_eq!(report.chunks, vec![Run(ReceivedSmallDelta, 2)]);
        assert_eq!(report.delta, vec![Small(48), Small(48)]);
    }

    #[test]
    fn truncated_counts_gaps_correctly() {
        let mut reg = TwccRecvRegister::new(100);

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
            vec![
                Run(ReceivedSmallDelta, 1),
                Run(NotReceived, 2),
                Run(ReceivedSmallDelta, 1)
            ]
        );
        assert_eq!(report.delta, vec![Small(0), Small(48)]);
    }

    #[test]
    fn run_max_is_8192() {
        let mut reg = TwccRecvRegister::new(100);

        let now = Instant::now();

        reg.update_seq(0.into(), now + Duration::from_millis(0));
        reg.update_seq(8194.into(), now + Duration::from_millis(10));

        let report = reg.build_report(1000).unwrap();

        assert_eq!(report.status_count, 8195);
        assert_eq!(
            report.chunks,
            vec![
                VectorSingle(8192, 14),
                Run(NotReceived, 8180),
                Run(ReceivedSmallDelta, 1)
            ]
        );
    }

    #[test]
    fn single_followed_by_missing() {
        let mut reg = TwccRecvRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(0));
        reg.update_seq(12.into(), now + Duration::from_millis(10));
        reg.update_seq(100.into(), now + Duration::from_millis(20));

        let report = reg.build_report(2016).unwrap();

        assert_eq!(report.status_count, 91);
        assert_eq!(
            report.chunks,
            vec![
                VectorSingle(10240, 14),
                Run(NotReceived, 76),
                Run(ReceivedSmallDelta, 1)
            ]
        );
        assert_eq!(report.delta, vec![Small(0), Small(40), Small(40)]);
    }

    #[test]
    fn time_jump_small_back_for_second_report() {
        let mut reg = TwccRecvRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(8000));
        let _ = reg.build_report(2016).unwrap();

        reg.update_seq(9.into(), now + Duration::from_millis(0));
        let report = reg.build_report(2016).unwrap();

        assert_eq!(report.status_count, 2);
        assert_eq!(report.chunks, vec![Run(ReceivedLargeOrNegativeDelta, 2)]);
        assert_eq!(report.delta, vec![Large(-32000), Large(32000)]);
    }

    #[test]
    fn time_jump_large_back_for_second_report() {
        let mut reg = TwccRecvRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(9000));
        let _ = reg.build_report(2016).unwrap();

        reg.update_seq(9.into(), now + Duration::from_millis(0));
        assert!(reg.build_report(2016).is_none());

        assert_eq!(reg.queue.len(), 1);
    }

    #[test]
    fn empty_twcc() {
        let twcc = Twcc {
            sender_ssrc: 0.into(),
            ssrc: 0.into(),
            base_seq: 0,
            status_count: 0,
            reference_time: 0,
            feedback_count: 0,
            chunks: VecDeque::new(),
            delta: VecDeque::new(),
        };

        let mut buf = vec![0_u8; 1500];
        let n = twcc.write_to(&mut buf[..]);
        buf.truncate(n);

        let header: RtcpHeader = (&buf[..]).try_into().unwrap();
        let parsed: Twcc = (&buf[4..]).try_into().unwrap();

        assert_eq!(header, twcc.header());
        assert_eq!(parsed, twcc);
    }

    #[test]
    fn negative_deltas() {
        let mut reg = TwccRecvRegister::new(100);

        let now = Instant::now();

        reg.update_seq(10.into(), now + Duration::from_millis(12));
        reg.update_seq(11.into(), now + Duration::from_millis(0));
        reg.update_seq(12.into(), now + Duration::from_millis(23));

        let report = reg.build_report(1000).unwrap();

        assert_eq!(report.status_count, 3);
        assert_eq!(report.base_seq, 10);
        assert_eq!(report.reference_time, 0);
        assert_eq!(report.chunks, vec![VectorDouble(6400, 7)]);
        assert_eq!(report.delta, vec![Small(0), Large(-48), Small(92)]);

        let base = reg.time_start.unwrap();

        let mut iter = report.into_iter(base, 10.into());
        assert_eq!(
            iter.next(),
            Some((
                10.into(),
                PacketStatus::ReceivedSmallDelta,
                Some(base + Duration::from_millis(0))
            ))
        );
        assert_eq!(
            iter.next(),
            Some((
                11.into(),
                PacketStatus::ReceivedLargeOrNegativeDelta,
                Some(base.checked_sub(Duration::from_millis(12)).unwrap())
            ))
        );
        assert_eq!(
            iter.next(),
            Some((
                12.into(),
                PacketStatus::ReceivedSmallDelta,
                Some(base + Duration::from_millis(11))
            ))
        );
    }

    #[test]
    fn twcc_fuzz_fail() {
        let mut reg = TwccRecvRegister::new(100);

        let now = Instant::now();

        // [Register(, ), Register(, ), Register(, ), BuildReport(43)]

        reg.update_seq(4542.into(), now + Duration::from_millis(2373281424));
        reg.update_seq(15918.into(), now + Duration::from_millis(2373862820));
        reg.update_seq(8405.into(), now + Duration::from_millis(2379074367));

        let report = reg.build_report(43).unwrap();

        let mut buf = vec![0_u8; 1500];
        let n = report.write_to(&mut buf[..]);
        buf.truncate(n);

        let header: RtcpHeader = match (&buf[..]).try_into() {
            Ok(v) => v,
            Err(_) => return,
        };
        let parsed: Twcc = match (&buf[4..]).try_into() {
            Ok(v) => v,
            Err(_) => return,
        };

        assert_eq!(header, report.header());
        assert_eq!(parsed, report);
    }

    #[test]
    fn twcc_large_time_delta_edges() {
        let mut reg = TwccRecvRegister::new(100);

        // Stretch the boundaries of the i16 type used for deltas
        let now = Instant::now();
        reg.update_seq(0.into(), now + Duration::from_micros(8_192_000));
        reg.update_seq(1.into(), now + Duration::from_micros(0));
        reg.update_seq(2.into(), now + Duration::from_micros(8_191_750));

        let report = reg.build_report(1000).unwrap();

        assert_eq!(report.status_count, 3);
        assert_eq!(report.delta, vec![Small(0), Large(-32768), Large(32767)]);
    }

    #[test]
    fn twcc_crazy_negative_time_delta() {
        let mut reg = TwccRecvRegister::new(100);

        // Deltas so big they wrap around the bounds of an i32 to become small again.
        // These constants are chosen carefully to look normal when wrapped
        let now = Instant::now();
        reg.update_seq(0.into(), now + Duration::from_micros(4_294_967_547)); // Wraps to -251
        reg.update_seq(1.into(), now + Duration::from_micros(0));

        // The bogus value should be ignored
        let report = reg.build_report(1000).unwrap();
        assert_eq!(report.status_count, 1);
        assert_eq!(report.delta, vec![Small(0)]);
    }

    #[test]
    fn twcc_crazy_positive_time_delta() {
        let mut reg = TwccRecvRegister::new(100);

        // Deltas so big they wrap around the bounds of an i32 to become small again.
        // These constants are chosen carefully to look normal when wrapped
        let now = Instant::now();
        reg.update_seq(0.into(), now + Duration::from_micros(0));
        reg.update_seq(1.into(), now + Duration::from_micros(4_294_967_547)); // Wraps to 251

        // The bogus value should be ignored
        let report = reg.build_report(1000).unwrap();
        assert_eq!(report.status_count, 1);
        assert_eq!(report.delta, vec![Small(0)]);
    }

    #[test]
    fn test_send_register_apply_report_for_old_seq_numbers() {
        let mut reg = TwccSendRegister::new(25);
        let mut now = Instant::now();

        for i in 0..50 {
            reg.register_seq(i.into(), now, 0);
            now = now + Duration::from_micros(15);
        }

        // At this point the front of the internal queue should be seq no 25.
        //
        // Set time zero base with empty packet
        reg.apply_report(
            Twcc {
                sender_ssrc: Ssrc::new(),
                ssrc: Ssrc::new(),
                base_seq: 0,
                status_count: 0,
                reference_time: 0,
                feedback_count: 0,
                chunks: [].into(),
                delta: [].into(),
            },
            now,
        );
        now = now + Duration::from_millis(35);

        let iter = reg.apply_report(
            Twcc {
                sender_ssrc: Ssrc::new(),
                ssrc: Ssrc::new(),
                base_seq: 20,
                status_count: 8,
                reference_time: 35,
                feedback_count: 0,
                chunks: [PacketChunk::Run(PacketStatus::ReceivedSmallDelta, 8)].into(),
                delta: [
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                ]
                .into(),
            },
            now,
        );
        let iter = iter.unwrap();

        for record in iter {
            assert!(
                record.recv_report.is_some(),
                "Report should have recorded recv_report"
            );
        }
    }

    #[test]
    fn test_twcc_iter_correct_deltas() {
        let twcc = Twcc {
            sender_ssrc: 0.into(),
            ssrc: 0.into(),
            base_seq: 1,
            status_count: 12,
            reference_time: 1337,
            feedback_count: 0,
            chunks: [
                PacketChunk::Run(PacketStatus::ReceivedSmallDelta, 2),
                PacketChunk::VectorDouble(0b1101_0010_0101_0000, 7),
                PacketChunk::Run(PacketStatus::ReceivedLargeOrNegativeDelta, 3),
            ]
            .into(),
            delta: [
                // Run of length 2
                Delta::Small(10),
                Delta::Small(15),
                // Double status vector with 4 deltas
                Delta::Small(7),
                Delta::Large(280),
                Delta::Small(3),
                Delta::Small(13),
                // Run of length 3
                Delta::Large(-37),
                Delta::Large(32),
                Delta::Large(89),
            ]
            .into(),
        };

        let now = Instant::now();
        let base = now + Duration::from_millis(1337 * 64);
        let expected = vec![
            (
                1.into(),
                PacketStatus::ReceivedSmallDelta,
                Some(base + Duration::from_micros(10 * 250)),
            ),
            (
                2.into(),
                PacketStatus::ReceivedSmallDelta,
                Some(base + Duration::from_micros(25 * 250)),
            ),
            (
                3.into(),
                PacketStatus::ReceivedSmallDelta,
                Some(base + Duration::from_micros(32 * 250)),
            ),
            (4.into(), PacketStatus::NotReceived, None),
            (
                5.into(),
                PacketStatus::ReceivedLargeOrNegativeDelta,
                Some(base + Duration::from_micros(312 * 250)),
            ),
            (
                6.into(),
                PacketStatus::ReceivedSmallDelta,
                Some(base + Duration::from_micros(315 * 250)),
            ),
            (
                7.into(),
                PacketStatus::ReceivedSmallDelta,
                Some(base + Duration::from_micros(328 * 250)),
            ),
            (8.into(), PacketStatus::NotReceived, None),
            (9.into(), PacketStatus::NotReceived, None),
            (
                10.into(),
                PacketStatus::ReceivedLargeOrNegativeDelta,
                Some(base + Duration::from_micros(291 * 250)),
            ),
            (
                11.into(),
                PacketStatus::ReceivedLargeOrNegativeDelta,
                Some(base + Duration::from_micros(323 * 250)),
            ),
            (
                12.into(),
                PacketStatus::ReceivedLargeOrNegativeDelta,
                Some(base + Duration::from_micros(412 * 250)),
            ),
        ];

        let result: Vec<_> = twcc.into_iter(now, 1.into()).collect();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_twcc_iter_limited_with_status_count() {
        let status_count = 3;

        // [(1, NotReceived), (2, ReceivedSmallDelta), (3, ReceivedSmallDelta)]
        let twcc_iter_count = Twcc {
            sender_ssrc: 1.into(),
            ssrc: 2.into(),
            base_seq: 1,
            status_count,
            reference_time: 406753,
            feedback_count: 1,
            chunks: VecDeque::from(vec![VectorDouble(0b00_00_01_01_00_00_00_00, 7)]),
            delta: VecDeque::from(vec![Small(236), Small(1)]),
        }
        .into_iter(Instant::now(), 1.into())
        .count();

        assert_eq!(twcc_iter_count, status_count as usize);
    }

    #[test]
    fn test_twcc_register_send_records() {
        let mut reg = TwccSendRegister::new(25);
        let mut now = Instant::now();
        for i in 0..25 {
            reg.register_seq(i.into(), now, 0);
            now = now + Duration::from_micros(15);
        }

        let iter = reg
            .apply_report(
                Twcc {
                    sender_ssrc: Ssrc::new(),
                    ssrc: Ssrc::new(),
                    base_seq: 0,
                    status_count: 8,
                    reference_time: 35,
                    feedback_count: 0,
                    chunks: [PacketChunk::Run(PacketStatus::ReceivedSmallDelta, 8)].into(),
                    delta: [
                        Delta::Small(10),
                        Delta::Small(10),
                        Delta::Small(10),
                        Delta::Small(10),
                        Delta::Small(10),
                        Delta::Small(10),
                        Delta::Small(10),
                        Delta::Small(10),
                    ]
                    .into(),
                },
                now,
            )
            .expect("apply_report to return Some(_)");

        assert_eq!(
            iter.map(|r| *r.seq).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 5, 6, 7]
        );
    }

    #[test]
    fn test_twcc_send_register_loss() {
        let mut reg = TwccSendRegister::new(25);
        let mut now = Instant::now();
        for i in 0..9 {
            reg.register_seq(i.into(), now, 0);
            now = now + Duration::from_millis(15);
        }

        now = now + Duration::from_millis(5);
        #[allow(unused_must_use)]
        reg.apply_report(
            Twcc {
                sender_ssrc: Ssrc::new(),
                ssrc: Ssrc::new(),
                base_seq: 0,
                status_count: 9,
                reference_time: 35,
                feedback_count: 0,
                chunks: [
                    PacketChunk::VectorDouble(0b11_01_01_01_00_01_00_01, 7),
                    PacketChunk::Run(PacketStatus::ReceivedSmallDelta, 2),
                ]
                .into(),
                delta: [
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                    Delta::Small(10),
                ]
                .into(),
            },
            now,
        )
        .expect("apply_report to return Some(_)");

        now = now + Duration::from_millis(20);
        let loss = reg
            .loss(Duration::from_millis(150), now)
            .expect("Should be able to calcualte loss");

        let pct = (loss * 100.0).floor() as u32;

        assert_eq!(
            pct, 25,
            "The loss percentage should be 25 as 2 out of 8 packets are lost"
        );
    }

    #[test]
    fn test_twcc_recv_register_loss() {
        let mut reg = TwccRecvRegister::new(25);
        let mut now = Instant::now();

        for i in 0..10 {
            if i == 3 || i == 7 {
                // simulate loss
                continue;
            }
            reg.update_seq(i.into(), now);
            now = now + Duration::from_millis(50);
        }

        assert_eq!(reg.loss(), Some(2.0 / 10.0));

        for i in 10..20 {
            if i == 11 || i == 13 || i == 15 || i == 17 {
                // simulate loss
                continue;
            }
            reg.update_seq(i.into(), now);
            now = now + Duration::from_millis(50);
        }

        assert_eq!(reg.loss(), Some(4.0 / 10.0));
    }

    #[test]
    fn no_acked_duplicates_when_reordered() {
        let now = Instant::now();
        let mut twcc_gen = TwccRecvRegister::new(1000);
        let mut twcc_handler = TwccSendRegister::new(1000);

        twcc_handler.register_seq(1.into(), now + Duration::from_millis(1), 0);
        twcc_handler.register_seq(2.into(), now + Duration::from_millis(2), 0);
        twcc_handler.register_seq(3.into(), now + Duration::from_millis(3), 0);
        twcc_handler.register_seq(4.into(), now + Duration::from_millis(4), 0);

        {
            let acked_packets = twcc_handler
                .apply_report(
                    {
                        // 3rd packet is delayed
                        twcc_gen.update_seq(1.into(), now + Duration::from_millis(5));
                        twcc_gen.update_seq(2.into(), now + Duration::from_millis(6));
                        twcc_gen.update_seq(4.into(), now + Duration::from_millis(7));
                        twcc_gen.build_report(10_000).unwrap()
                    },
                    now + Duration::from_millis(8),
                )
                .unwrap()
                .filter_map(|sr| sr.remote_recv_time().map(|_| sr.seq.as_u16()))
                .collect::<Vec<_>>();

            assert_eq!(acked_packets, [1, 2, 4]);
        }

        twcc_handler.register_seq(5.into(), now + Duration::from_millis(9), 0);
        twcc_handler.register_seq(6.into(), now + Duration::from_millis(10), 0);
        twcc_handler.register_seq(7.into(), now + Duration::from_millis(11), 0);

        {
            let acked_packets = twcc_handler
                .apply_report(
                    {
                        // So the receipt order is 1, 2, 4, 3, 7
                        twcc_gen.update_seq(3.into(), now + Duration::from_millis(12));
                        twcc_gen.update_seq(7.into(), now + Duration::from_millis(13));
                        twcc_gen.build_report(10_000).unwrap()
                    },
                    now + Duration::from_millis(14),
                )
                .unwrap()
                .filter_map(|sr| sr.remote_recv_time().map(|_| sr.seq.as_u16()))
                .collect::<Vec<_>>();

            // 3 was delayed before and is acked now
            // 4 is excluded since it was already returned from the previous call
            // [5, 6] are delayed/lost
            // 7 is acked in the last report
            assert_eq!(acked_packets, [3, 7]);
        }
    }
}
