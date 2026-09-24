use std::collections::VecDeque;
use std::fmt;
use std::ops::{Range, RangeInclusive};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::rtp::vla::VideoLayersAllocation;
use crate::rtp_::{ExtensionValues, MediaTime, RtpHeader, SenderInfo, SeqNo};

use super::contiguity::Contiguity;
use super::contiguity_vp8::Vp8Contiguity;
use super::contiguity_vp9::Vp9Contiguity;
use super::{CodecDepacketizer, CodecExtra, Depacketizer, PacketError};

// Bound incomplete frames as well as complete frames waiting for reordering.
// 4,096 packets allow roughly 5 MB of payload at a typical 1,200-byte packet size.
const MAX_BUFFERED_PACKETS: usize = 4096;

#[derive(Clone, PartialEq, Eq)]
/// Holds metadata incoming RTP data.
pub struct RtpMeta {
    /// When this RTP packet was received.
    pub received: Instant,
    /// Media time translated from the RtpHeader time.
    pub time: MediaTime,
    /// Sequence number, extended from the RTPHeader.
    pub seq_no: SeqNo,
    /// The actual header.
    pub header: RtpHeader,
    /// Sender information from the most recent Sender Report(SR).
    ///
    /// If no Sender Report(SR) has been received this is [`None`].
    pub last_sender_info: Option<SenderInfo>,
}

#[derive(Clone)]
pub struct Depacketized {
    pub time: MediaTime,
    pub contiguous: bool,
    pub meta: Vec<RtpMeta>,
    pub data: Vec<u8>,
    pub codec_extra: CodecExtra,
}

impl Depacketized {
    pub fn first_network_time(&self) -> Instant {
        self.meta
            .iter()
            .map(|m| m.received)
            .min()
            .expect("a depacketized to consist of at least one packet")
    }

    pub fn first_sender_info(&self) -> Option<SenderInfo> {
        self.meta
            .iter()
            .min_by_key(|m| m.received)
            .map(|m| m.last_sender_info)
            .expect("a depacketized to consist of at least one packet")
    }

    pub fn seq_range(&self) -> RangeInclusive<SeqNo> {
        let first = self
            .meta
            .first()
            .expect("a depacketized to consist of at least one packet")
            .seq_no;
        let last = self
            .meta
            .last()
            .expect("a depacketized to consist of at least one packet")
            .seq_no;
        first..=last
    }

    pub fn start_of_talkspurt(&self) -> bool {
        self.meta
            .first()
            .expect("a depacketized to consist of at least one packet")
            .header
            .marker
    }

    pub fn ext_vals(&self) -> ExtensionValues {
        let last = &self
            .meta
            .last()
            .expect("depacketized video frame must contain a trailing packet")
            .header
            .ext_vals;

        let first = &self
            .meta
            .first()
            .expect("depacketized video frame must contain a leading packet")
            .header
            .ext_vals;

        // We use the extensions from the last packet because certain extensions, such as video
        // orientation, are only added on the last packet to save bytes.
        let mut merged = last.clone();

        // str0m strictly attaches some fields to the first packet of a frame.
        if let Some(first_val) = &first.abs_capture_time {
            merged.abs_capture_time = Some(*first_val);
        }

        if let Some(first_val) = first.user_values.get_arc::<VideoLayersAllocation>() {
            merged.user_values.set_arc(first_val);
        }

        merged
    }
}

#[derive(Debug)]
struct Entry {
    meta: RtpMeta,
    data: Arc<[u8]>,
    head: bool,
    tail: bool,
}

#[derive(Debug)]
pub struct DepacketizingBuffer {
    hold_back: usize,
    depack: CodecDepacketizer,
    queue: VecDeque<Entry>,
    // Segment indices are relative to the queue at the last rebuild.
    segments: VecDeque<(usize, usize, Instant)>,
    segments_dirty: bool,
    segments_offset: usize,
    #[cfg(test)]
    segment_rebuilds: usize,
    last_emitted: Option<(SeqNo, CodecExtra)>,
    max_time: Option<MediaTime>,
    depack_cache: Option<(Range<usize>, Depacketized)>,
    contiguity: Contiguity,
}

impl DepacketizingBuffer {
    pub(crate) fn new(depack: CodecDepacketizer, hold_back: usize) -> Self {
        let contiguity = match depack {
            CodecDepacketizer::Vp8(_) => Contiguity::Vp8(Vp8Contiguity::new()),
            CodecDepacketizer::Vp9(_) => Contiguity::Vp9(Vp9Contiguity::new()),
            CodecDepacketizer::H264(_)
            | CodecDepacketizer::H265(_)
            | CodecDepacketizer::H266(_)
            | CodecDepacketizer::Av1(_)
            | CodecDepacketizer::Boxed(_)
            | CodecDepacketizer::Opus(_)
            | CodecDepacketizer::ComfortNoise(_)
            | CodecDepacketizer::Tele(_)
            | CodecDepacketizer::G711(_)
            | CodecDepacketizer::Null(_) => Contiguity::None,
        };

        DepacketizingBuffer {
            hold_back,
            depack,
            queue: VecDeque::new(),
            segments: VecDeque::new(),
            segments_dirty: false,
            segments_offset: 0,
            #[cfg(test)]
            segment_rebuilds: 0,
            last_emitted: None,
            max_time: None,
            depack_cache: None,
            contiguity,
        }
    }

    pub fn push(&mut self, meta: RtpMeta, data: impl Into<Arc<[u8]>>) {
        self.push_entry(meta, data.into(), None);
    }

    pub(crate) fn push_padding(&mut self, meta: RtpMeta) {
        self.push_entry(meta, Arc::from([]), Some((false, false)));
    }

    fn push_entry(&mut self, meta: RtpMeta, data: Arc<[u8]>, partition: Option<(bool, bool)>) {
        // We're not emitting frames in the wrong order. If we receive
        // packets that are before the last emitted, we drop.
        //
        // As a special case, per popular demand, if hold_back is 0, we do emit
        // out of order packets.
        if let Some((last, _)) = self.last_emitted {
            if meta.seq_no <= last && self.hold_back > 0 {
                trace!("Drop before emitted: {} <= {}", meta.seq_no, last);
                return;
            }
        }

        // Record that latest seen max time (used for extending time to u64).
        self.max_time = Some(if let Some(m) = self.max_time {
            m.max(meta.time)
        } else {
            meta.time
        });

        match self
            .queue
            .binary_search_by_key(&meta.seq_no, |r| r.meta.seq_no)
        {
            Ok(_) => {
                // exact same seq_no found. ignore
                trace!("Drop exactly same packet: {}", meta.seq_no);
            }
            Err(mut i) => {
                if self.queue.len() == MAX_BUFFERED_PACKETS {
                    if i == 0 {
                        // This packet is older than everything we can retain.
                        return;
                    }
                    self.queue.pop_front();
                    self.depack_cache = None;
                    i -= 1;
                }

                let (head, tail) = partition.unwrap_or_else(|| {
                    (
                        self.depack.is_partition_head(data.as_ref()),
                        self.depack
                            .is_partition_tail(meta.header.marker, data.as_ref()),
                    )
                });

                // i is insertion point to maintain order
                let entry = Entry {
                    meta,
                    data,
                    head,
                    tail,
                };
                self.queue.insert(i, entry);
                self.segments_dirty = true;

                // The depack cache is keyed by queue index. Inserting at or before the cached
                // segment shifts it, so the cache would answer for the wrong packets.
                if let Some((range, _)) = &self.depack_cache {
                    if i <= range.end {
                        self.depack_cache = None;
                    }
                }
            }
        }
    }

    pub fn pop(
        &mut self,
        now: Instant,
        reordering_timeout: Option<Duration>,
    ) -> Option<Result<Depacketized, PacketError>> {
        loop {
            let queued = self.queue.len();
            let result = self.pop_frame(now, reordering_timeout);
            if result.is_some() || reordering_timeout.is_none() || self.queue.len() == queued {
                return result;
            }
            // A discarded frame must not leave later frames waiting for new input.
        }
    }

    fn pop_frame(
        &mut self,
        now: Instant,
        reordering_timeout: Option<Duration>,
    ) -> Option<Result<Depacketized, PacketError>> {
        self.update_segments();

        if self.segments.is_empty() {
            self.discard_old_padding();
            return None;
        }

        // println!(
        //     "{:?} {:?}",
        //     self.queue.iter().map(|e| e.meta.seq_no).collect::<Vec<_>>(),
        //     self.segments
        // );

        let (start, stop, first_received) = self.first_segment().expect("segment exists");

        let seq = {
            let last = self.queue.get(stop).expect("entry for stop index");
            last.meta.seq_no
        };

        // depack ahead, even if we may not emit right away
        let mut dep = match self.depacketize(start, stop, seq) {
            Ok(d) => d,
            Err(e) => {
                // this segment cannot be decoded correctly
                // remove from the queue and return the error
                self.last_emitted = Some((seq, CodecExtra::None));
                self.consume_segment(stop);
                return Some(Err(e));
            }
        };

        // If we have contiguity of seq numbers we emit right away,
        // Otherwise, we wait for retransmissions up to `hold_back` frames
        // and re-evaluate contiguity based on codec specific information

        let more_than_hold_back = self.segments.len() >= self.hold_back;
        let contiguous_seq = self.is_following_last(start);
        let wait_for_contiguity = !contiguous_seq
            && !more_than_hold_back
            && !self.timeout_allows_progress(now, first_received, reordering_timeout);

        if wait_for_contiguity {
            // if we are not sending, cache the depacked
            self.depack_cache = Some((start..stop, dep));
            self.discard_old_padding();
            return None;
        }

        let (can_emit, contiguous_codec) = self.contiguity.check(&dep.codec_extra, contiguous_seq);
        dep.contiguous = contiguous_codec;

        let last = self
            .queue
            .get(stop)
            .expect("entry for stop index")
            .meta
            .seq_no;

        // Keep the same RTP entry until every packed report has been emitted. The next pop
        // depacketizes its remaining bytes, so sequence ordering and duplicate checks stay intact.
        let is_tele = matches!(self.depack, CodecDepacketizer::Tele(_));
        let has_more_reports = dep.data.len() > 4;
        if can_emit && is_tele && has_more_reports {
            self.retain_tele_reports(start, &mut dep);
            return Some(Ok(dep));
        }

        // We're not going to emit frames in the incorrect order, there's no point in keeping
        // stuff before the emitted range.
        self.consume_segment(stop);

        if !can_emit {
            return None;
        }

        self.last_emitted = Some((last, dep.codec_extra));

        Some(Ok(dep))
    }

    fn retain_tele_reports(&mut self, start: usize, dep: &mut Depacketized) {
        let duration = u16::from_be_bytes([dep.data[2], dep.data[3]]);
        let remaining = dep.data.split_off(4);
        let entry = self.queue.get_mut(start).expect("telephone packet exists");
        entry.data = remaining.into();
        entry.meta.time = MediaTime::new(
            entry.meta.time.numer().wrapping_add(u64::from(duration)),
            entry.meta.time.frequency(),
        );
        entry.meta.header.marker = false;
        self.segments_dirty = true;
        self.depack_cache = None;
    }

    pub(crate) fn poll_timeout(&mut self, reordering_timeout: Option<Duration>) -> Option<Instant> {
        let timeout = reordering_timeout?;
        self.update_segments();

        let (start, _, first_received) = self.first_segment()?;

        let contiguous_seq = self.is_following_last(start);
        let more_than_hold_back = self.segments.len() >= self.hold_back;
        if contiguous_seq || more_than_hold_back {
            return None;
        }

        // No representable input time can reach a deadline beyond Instant's range.
        first_received.checked_add(timeout)
    }

    fn discard_old_padding(&mut self) {
        let original_len = self.queue.len();
        let is_padding = |entry: &Entry| entry.data.is_empty() && !entry.head && !entry.tail;

        if let Some((mut last, extra)) = self.last_emitted {
            while self.queue.len() > self.hold_back {
                let entry = self.queue.front().expect("queue exceeds hold back");
                if !is_padding(entry) {
                    break;
                }

                if last.is_next(entry.meta.seq_no) {
                    last = entry.meta.seq_no;
                }
                self.queue.pop_front();
            }

            self.last_emitted = Some((last, extra));
        }

        // An incomplete frame can remain at the front while another payload type
        // contributes synthetic padding indefinitely. Keep the frame, but retain
        // only the newest padding needed for the reordering window. Padding removed
        // from behind media cannot advance last_emitted across that media.
        let mut excess_padding = self
            .queue
            .iter()
            .filter(|entry| is_padding(entry))
            .count()
            .saturating_sub(self.hold_back);
        self.queue.retain(|entry| {
            if excess_padding > 0 && is_padding(entry) {
                excess_padding -= 1;
                false
            } else {
                true
            }
        });

        if self.queue.len() != original_len {
            self.segments_dirty = true;
            self.depack_cache = None;
        }
    }

    fn timeout_allows_progress(
        &self,
        now: Instant,
        first_received: Instant,
        reordering_timeout: Option<Duration>,
    ) -> bool {
        let Some(timeout) = reordering_timeout else {
            return false;
        };

        now.checked_duration_since(first_received)
            .is_some_and(|age| age >= timeout)
    }

    fn depacketize(
        &mut self,
        start: usize,
        stop: usize,
        _seq: SeqNo,
    ) -> Result<Depacketized, PacketError> {
        if let Some(cached) = self.depack_cache.take() {
            if cached.0 == (start..stop) {
                trace!("depack cache hit for segment start {}", start);
                return Ok(cached.1);
            }
        }

        let packets_size = self.queue.range(start..=stop).map(|p| p.data.len()).sum();
        let mut data = self
            .depack
            .out_size_hint(packets_size)
            .map(Vec::with_capacity)
            .unwrap_or_else(Vec::new);
        let mut codec_extra = CodecExtra::None;

        let time = self.queue.get(start).expect("first index exist").meta.time;
        let mut meta = Vec::with_capacity(stop - start + 1);

        for entry in self.queue.range_mut(start..=stop) {
            self.depack
                .depacketize(entry.data.as_ref(), &mut data, &mut codec_extra)?;
            meta.push(entry.meta.clone());
        }

        Ok(Depacketized {
            time,
            contiguous: true, // the caller taking ownership will modify this accordingly
            meta,
            data,
            codec_extra,
        })
    }

    fn first_segment(&self) -> Option<(usize, usize, Instant)> {
        self.segments.front().map(|&(start, stop, received)| {
            (
                start - self.segments_offset,
                stop - self.segments_offset,
                received,
            )
        })
    }

    fn consume_segment(&mut self, stop: usize) {
        // Removing the first segment leaves later boundaries intact. Advance the
        // index origin instead of rescanning packets or shifting every segment.
        self.queue.drain(0..=stop);
        self.segments.pop_front();
        self.segments_offset += stop + 1;
    }

    fn update_segments(&mut self) {
        if !self.segments_dirty {
            return;
        }
        self.segments_dirty = false;
        self.segments_offset = 0;
        #[cfg(test)]
        {
            self.segment_rebuilds += 1;
        }
        self.segments.clear();

        #[derive(Clone, Copy)]
        struct Start {
            index: i64,
            time: MediaTime,
            offset: i64,
            first_received: Instant,
        }

        let mut start: Option<Start> = None;

        for (index, entry) in self.queue.iter().enumerate() {
            let index = index as i64;
            let iseq = *entry.meta.seq_no as i64;
            let expected_seq = start.map(|s| s.offset.saturating_add(index));

            let is_expected_seq = expected_seq == Some(iseq);
            let is_same_timestamp = start.map(|s| s.time) == Some(entry.meta.time);
            let is_defacto_tail = is_expected_seq && !is_same_timestamp;

            if start.is_some() && is_defacto_tail {
                // We found a segment that ended because the timestamp changed without
                // a gap in the sequence number. The marker bit in the RTP packet is
                // just indicative, this is the robust fallback.
                let s = start.unwrap();
                let segment = (s.index as usize, index as usize - 1, s.first_received);
                self.segments.push_back(segment);
                start = None;
            }

            if start.is_some() && (!is_expected_seq || !is_same_timestamp) {
                // Not contiguous. Start looking again.
                start = None;
            }

            // Each segment can have multiple is_partition_head() == true, record the first.
            if start.is_none() && entry.head {
                start = Some(Start {
                    index,
                    time: entry.meta.time,
                    offset: iseq.saturating_sub(index),
                    first_received: entry.meta.received,
                });
            }

            if let Some(s) = start.as_mut() {
                s.first_received = s.first_received.min(entry.meta.received);
            }

            if start.is_some() && entry.tail {
                // We found a contiguous sequence of packets ending with something from
                // the packet (like the RTP marker bit) indicating it's the tail.
                let s = start.unwrap();
                let segment = (s.index as usize, index as usize, s.first_received);
                self.segments.push_back(segment);
                start = None;
            }
        }
    }

    fn is_following_last(&self, start: usize) -> bool {
        let Some((last, _)) = self.last_emitted else {
            // First time we emit something.
            return true;
        };

        // track sequence numbers are sequential
        let mut seq = last;

        // Expect all entries before start to be padding.
        for entry in self.queue.range(0..start) {
            if !seq.is_next(entry.meta.seq_no) {
                // Not a sequence
                return false;
            }
            // for next loop round.
            seq = entry.meta.seq_no;

            let is_padding = entry.data.is_empty() && !entry.head && !entry.tail;
            if !is_padding {
                return false;
            }
        }

        let start_entry = self.queue.get(start).expect("entry for start index");

        seq.is_next(start_entry.meta.seq_no)
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
        f.debug_struct("Depacketized")
            .field("time", &self.time)
            .field("meta", &self.meta)
            .field("data", &self.data.len())
            .finish()
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant, SystemTime};

    use super::*;
    use crate::packet::vp9::Vp9Depacketizer;
    use crate::rtp::UserExtensionValues;
    use crate::rtp_::{AbsCaptureTime, Frequency, MediaTime, Pt, Ssrc, VideoOrientation};

    fn bounded_queue_meta(seq: u64) -> RtpMeta {
        RtpMeta {
            received: Instant::now(),
            seq_no: seq.into(),
            time: MediaTime::from_90khz(seq),
            last_sender_info: None,
            header: RtpHeader::default(),
        }
    }

    #[test]
    fn incomplete_frames_cannot_grow_queue_forever() {
        for hold_back in [0, 3] {
            let mut buf =
                DepacketizingBuffer::new(CodecDepacketizer::Vp8(Default::default()), hold_back);
            for i in 0..MAX_BUFFERED_PACKETS * 2 {
                // Frame heads with gaps and no tails never form a complete segment.
                buf.push(bounded_queue_meta((i * 2) as u64), [0x10, 0]);
                assert!(buf.pop(Instant::now(), None).is_none());
            }
            assert!(buf.queue.len() <= MAX_BUFFERED_PACKETS);

            // A new complete keyframe must still get through after the overflow.
            let seq = (MAX_BUFFERED_PACKETS * 4) as u64;
            let mut meta = bounded_queue_meta(seq);
            meta.header.marker = true;
            buf.push(meta, [0x10, 0]);
            let frame = buf.pop(Instant::now(), None).unwrap().unwrap();
            assert_eq!(*frame.seq_range().start(), seq.into());
        }
    }

    #[test]
    fn queue_overflow_discards_cached_frame_and_preserves_gap() {
        let mut buf = DepacketizingBuffer::new(
            CodecDepacketizer::Boxed(Box::new(TestDepack)),
            MAX_BUFFERED_PACKETS,
        );
        buf.push(bounded_queue_meta(1), [1, 1, 9]);
        assert!(buf.pop(Instant::now(), None).unwrap().unwrap().contiguous);
        buf.push(bounded_queue_meta(3), [1, 3, 9]);
        assert!(buf.pop(Instant::now(), None).is_none());
        assert!(buf.depack_cache.is_some());

        // Fill without polling. Evict the cached frame when the queue overflows.
        for seq in 4..=MAX_BUFFERED_PACKETS as u64 + 3 {
            buf.push(bounded_queue_meta(seq), [1, 4, 9]);
        }
        assert_eq!(buf.queue.len(), MAX_BUFFERED_PACKETS);
        let frame = buf.pop(Instant::now(), None).unwrap().unwrap();
        assert_eq!(*frame.seq_range().start(), 4.into());
        assert_eq!(frame.data, [1, 4, 9]);
        assert!(!frame.contiguous);
    }

    #[test]
    fn full_queue_ignores_older_packets_and_duplicates() {
        let mut buf = DepacketizingBuffer::new(CodecDepacketizer::Boxed(Box::new(TestDepack)), 3);
        for seq in 2..=MAX_BUFFERED_PACKETS as u64 + 1 {
            buf.push(bounded_queue_meta(seq), [0]);
        }
        buf.push(bounded_queue_meta(1), [0]);
        buf.push(bounded_queue_meta(2), [0]);
        assert_eq!(buf.queue.len(), MAX_BUFFERED_PACKETS);
        assert_eq!(buf.queue.front().unwrap().meta.seq_no, 2.into());
        assert_eq!(
            buf.queue.back().unwrap().meta.seq_no,
            (MAX_BUFFERED_PACKETS as u64 + 1).into()
        );
    }

    #[test]
    fn telephone_event_reports_malformed_payloads_and_recovers() {
        let base = Instant::now();
        let report = [5, 0x8a, 0, 160];
        let packed = [report, report].concat();

        for len in [0, 1, 2, 3, 5, 6, 7] {
            let mut buf = DepacketizingBuffer::new(crate::format::Codec::Tele.into(), 0);
            buf.push(test_meta(base, 1, 1, 0), &packed[..len]);
            assert!(matches!(
                buf.pop(base, None),
                Some(Err(PacketError::InvalidTelephoneEvent(
                    "payload must contain one or more complete 4-byte reports"
                )))
            ));
            assert!(buf.queue.is_empty());
            assert!(buf.pop(base, None).is_none());

            let mut meta = test_meta(base, 2, 1, 0);
            meta.header.marker = true;
            buf.push(meta, packed.clone());
            let first = buf.pop(base, None).unwrap().unwrap();
            assert_eq!(first.data, report);
            assert!(first.contiguous);
            assert!(first.start_of_talkspurt());
            let second = buf.pop(base, None).unwrap().unwrap();
            assert_eq!(second.data, report);
            assert_eq!(second.time.numer(), first.time.numer() + 160);
            assert!(!second.start_of_talkspurt());
            assert!(buf.pop(base, None).is_none());

            buf.push_padding(test_meta(base, 3, 2, 0));
            assert!(buf.pop(base, None).is_none());
            buf.push(test_meta(base, 4, 3, 0), report);
            let frame = buf.pop(base, None).unwrap().unwrap();
            assert_eq!(frame.data, report);
            assert!(frame.contiguous);
        }
    }

    #[test]
    fn end_on_marker() {
        test(&[
            //
            (1, 1, &[1], &[]),
            (2, 1, &[9], &[(1, &[1, 9])]),
        ])
    }

    #[test]
    fn late_packet_in_front_of_waiting_frame() {
        // Seq 3 is late. Seq 4 arrives first and waits for contiguity (it is depacketized ahead
        // and cached). When 3 then arrives it is inserted in front of 4, and both must come out
        // as themselves: 3 must not be emitted with 4's data.
        test_n(
            15,
            &[
                (1, 1, &[1, 1, 9], &[(1, &[1, 1, 9])]),
                (2, 2, &[1, 2, 9], &[(2, &[1, 2, 9])]),
                (4, 4, &[1, 4, 9], &[]),
                (3, 3, &[1, 3, 9], &[(3, &[1, 3, 9]), (4, &[1, 4, 9])]),
            ],
        )
    }

    #[test]
    fn ext_vals_extracts_from_first_and_last_packet() {
        let first_time = Instant::now();
        let abs_capture_time = AbsCaptureTime {
            capture_time: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            clock_offset: None,
        };
        let mut vla = UserExtensionValues::default();
        vla.set(VideoLayersAllocation {
            current_simulcast_stream_index: 1,
            simulcast_streams: vec![],
        });

        let first_header = RtpHeader {
            version: 2,
            has_padding: false,
            has_extension: true,
            csrc_count: 0,
            marker: false,
            payload_type: Pt::new_with_value(98),
            sequence_number: 1,
            timestamp: 100,
            ssrc: Ssrc::from(42),
            csrc: [0; 15],
            ext_vals: ExtensionValues {
                abs_capture_time: Some(abs_capture_time),
                user_values: vla.clone(),
                ..Default::default()
            },
            header_len: 0,
        };

        let last_header = RtpHeader {
            ext_vals: ExtensionValues {
                video_orientation: Some(VideoOrientation::Deg90),
                ..Default::default()
            },
            ..first_header.clone()
        };

        let time_value = 100_u64;
        let dep = Depacketized {
            time: MediaTime::new(time_value, Frequency::new(90000).unwrap()),
            contiguous: true,
            meta: vec![
                RtpMeta {
                    received: first_time,
                    time: MediaTime::new(time_value, Frequency::new(90000).unwrap()),
                    seq_no: SeqNo::from(1u64),
                    header: first_header,
                    last_sender_info: None,
                },
                RtpMeta {
                    received: first_time + Duration::from_millis(1),
                    time: MediaTime::new(time_value, Frequency::new(90000).unwrap()),
                    seq_no: SeqNo::from(2u64),
                    header: last_header,
                    last_sender_info: None,
                },
            ],
            data: Vec::new(),
            codec_extra: CodecExtra::None,
        };

        let merged = dep.ext_vals();
        assert_eq!(
            merged.abs_capture_time.unwrap().capture_time,
            abs_capture_time.capture_time
        );
        assert_eq!(
            merged
                .user_values
                .get::<VideoLayersAllocation>()
                .unwrap()
                .current_simulcast_stream_index,
            vla.get::<VideoLayersAllocation>()
                .unwrap()
                .current_simulcast_stream_index,
        );
        assert_eq!(merged.video_orientation, Some(VideoOrientation::Deg90));
    }

    #[test]
    fn end_on_defacto() {
        test(&[
            (1, 1, &[1], &[]),
            (2, 1, &[2], &[]),
            (3, 2, &[3], &[(1, &[1, 2])]),
        ])
    }

    #[test]
    fn skip_padding() {
        test(&[
            (1, 1, &[1], &[]),
            (2, 1, &[9], &[(1, &[1, 9])]),
            (3, 1, &[], &[]), // padding!
            (4, 2, &[1], &[]),
            (5, 2, &[9], &[(2, &[1, 9])]),
        ])
    }

    #[test]
    fn gap_after_emit() {
        test(&[
            (1, 1, &[1], &[]),
            (2, 1, &[9], &[(1, &[1, 9])]),
            // gap
            (4, 2, &[1], &[]),
            (5, 2, &[9], &[]),
        ])
    }

    #[test]
    fn gap_after_padding() {
        test(&[
            (1, 1, &[1], &[]),
            (2, 1, &[9], &[(1, &[1, 9])]),
            (3, 1, &[], &[]), // padding!
            // gap
            (5, 2, &[1], &[]),
            (6, 2, &[9], &[]),
        ])
    }

    #[test]
    fn single_packets() {
        test(&[
            (1, 1, &[1, 9], &[(1, &[1, 9])]),
            (2, 2, &[1, 9], &[(2, &[1, 9])]),
            (3, 3, &[1, 9], &[(3, &[1, 9])]),
            (4, 4, &[1, 9], &[(4, &[1, 9])]),
        ])
    }

    #[test]
    fn packets_out_of_order() {
        test(&[
            (1, 1, &[1], &[]),
            (2, 1, &[9], &[(1, &[1, 9])]),
            (4, 2, &[9], &[]),
            (3, 2, &[1], &[(2, &[1, 9])]),
        ])
    }

    #[test]
    fn packets_after_hold_out() {
        test(&[
            (1, 1, &[1, 9], &[(1, &[1, 9])]),
            (3, 3, &[1, 9], &[]),
            (4, 4, &[1, 9], &[]),
            (5, 5, &[1, 9], &[(3, &[1, 9]), (4, &[1, 9]), (5, &[1, 9])]),
        ])
    }

    #[test]
    fn packets_with_hold_0() {
        test0(&[
            (1, 1, &[1, 9], &[(1, &[1, 9])]),
            (3, 3, &[1, 9], &[(3, &[1, 9])]),
            (4, 4, &[1, 9], &[(4, &[1, 9])]),
            (5, 5, &[1, 9], &[(5, &[1, 9])]),
        ])
    }

    #[test]
    fn out_of_order_packets_with_hold_0() {
        test0(&[
            (3, 1, &[1, 9], &[(1, &[1, 9])]),
            (1, 3, &[1, 9], &[(3, &[1, 9])]),
            (5, 4, &[1, 9], &[(4, &[1, 9])]),
            (2, 5, &[1, 9], &[(5, &[1, 9])]),
        ])
    }

    #[test]
    fn padding_only_run_does_not_grow_the_queue_without_bound() {
        let depack = CodecDepacketizer::Boxed(Box::new(TestDepack));
        let mut buf = DepacketizingBuffer::new(depack, 3);
        let meta = |seq: u64| RtpMeta {
            received: Instant::now(),
            seq_no: seq.into(),
            time: MediaTime::from_90khz(seq),
            last_sender_info: None,
            header: RtpHeader {
                sequence_number: seq as u16,
                timestamp: seq as u32,
                ..Default::default()
            },
        };

        // Emit one packet for this PT, then model a long run on another PT.
        buf.push(meta(1), vec![1, 9]);
        assert!(buf.pop(Instant::now(), None).is_some());

        for seq in 2..=1_001 {
            buf.push_padding(meta(seq));
            assert!(buf.pop(Instant::now(), None).is_none());
        }

        assert!(
            buf.queue.len() <= buf.hold_back,
            "padding-only queue retained {} entries after a 1,000-packet run",
            buf.queue.len()
        );

        // Returning to this PT after compaction must still be contiguous with the last packet.
        buf.push(meta(1_002), vec![1, 9]);
        let dep = buf
            .pop(Instant::now(), None)
            .expect("packet emitted")
            .expect("valid packet");
        assert!(dep.contiguous);
    }

    #[test]
    fn padding_only_run_with_loss_stays_bounded_and_reports_discontinuity() {
        let depack = CodecDepacketizer::Boxed(Box::new(TestDepack));
        let mut buf = DepacketizingBuffer::new(depack, 3);
        let meta = |seq: u64| RtpMeta {
            received: Instant::now(),
            seq_no: seq.into(),
            time: MediaTime::from_90khz(seq),
            last_sender_info: None,
            header: RtpHeader {
                sequence_number: seq as u16,
                timestamp: seq as u32,
                ..Default::default()
            },
        };

        buf.push(meta(1), vec![1, 9]);
        assert!(buf.pop(Instant::now(), None).is_some());

        // Sequence 2 is lost while another PT remains active.
        for seq in 3..=1_002 {
            buf.push_padding(meta(seq));
            assert!(buf.pop(Instant::now(), None).is_none());
        }

        assert!(buf.queue.len() <= buf.hold_back);

        // A discontinuity waits for the normal hold-back before it is emitted.
        buf.push(meta(1_003), vec![1, 9]);
        assert!(buf.pop(Instant::now(), None).is_none());
        buf.push(meta(1_004), vec![1, 9]);
        assert!(buf.pop(Instant::now(), None).is_none());
        buf.push(meta(1_005), vec![1, 9]);
        let dep = buf
            .pop(Instant::now(), None)
            .expect("packet emitted")
            .expect("valid packet");
        assert!(!dep.contiguous);
    }

    #[test]
    fn padding_after_incomplete_vp8_frame_does_not_grow_without_bound() {
        let depack = CodecDepacketizer::Vp8(Default::default());
        let mut buf = DepacketizingBuffer::new(depack, 3);
        let meta = |seq: u64, marker: bool| RtpMeta {
            received: Instant::now(),
            seq_no: seq.into(),
            time: MediaTime::from_90khz(seq),
            last_sender_info: None,
            header: RtpHeader {
                marker,
                sequence_number: seq as u16,
                timestamp: seq as u32,
                ..Default::default()
            },
        };

        // Emit one complete VP8 frame for this PT.
        buf.push(meta(1, true), [0x10, 0x00]);
        assert!(buf.pop(Instant::now(), None).is_some());

        // The next frame's head is lost, leaving an S=0 fragment at the front.
        buf.push(meta(2, false), [0x00]);
        assert!(buf.pop(Instant::now(), None).is_none());

        // The sender switches PT. Every packet becomes synthetic padding here.
        for seq in 3..=1_002 {
            buf.push_padding(meta(seq, false));
            assert!(buf.pop(Instant::now(), None).is_none());
        }

        assert!(
            buf.queue.len() <= buf.hold_back + 1,
            "incomplete VP8 frame retained {} entries after a 1,000-packet PT switch",
            buf.queue.len()
        );
    }

    #[test]
    fn padding_after_waiting_vp8_frame_does_not_grow_without_bound() {
        let depack = CodecDepacketizer::Vp8(Default::default());
        let mut buf = DepacketizingBuffer::new(depack, 3);
        let meta = |seq: u64, marker: bool| RtpMeta {
            received: Instant::now(),
            seq_no: seq.into(),
            time: MediaTime::from_90khz(seq),
            last_sender_info: None,
            header: RtpHeader {
                marker,
                sequence_number: seq as u16,
                timestamp: seq as u32,
                ..Default::default()
            },
        };

        buf.push(meta(1, true), [0x10, 0x00]);
        assert!(buf.pop(Instant::now(), None).is_some());

        // Lose a frame head, then switch away long enough to compact its padding.
        buf.push(meta(2, false), [0x00]);
        assert!(buf.pop(Instant::now(), None).is_none());
        for seq in 3..=1_002 {
            buf.push_padding(meta(seq, false));
            assert!(buf.pop(Instant::now(), None).is_none());
        }

        // One complete frame returns, but waits behind the orphan for hold-back.
        buf.push(meta(1_003, true), [0x10, 0x00]);
        assert!(buf.pop(Instant::now(), None).is_none());

        // Switching away again must remain bounded while that frame waits.
        for seq in 1_004..=2_003 {
            buf.push_padding(meta(seq, false));
            assert!(buf.pop(Instant::now(), None).is_none());
        }

        assert!(
            buf.queue.len() <= buf.hold_back + 2,
            "waiting VP8 frame retained {} entries after a second 1,000-packet PT switch",
            buf.queue.len()
        );
    }

    #[test]
    fn padding_after_initial_incomplete_vp8_frame_does_not_grow_without_bound() {
        let depack = CodecDepacketizer::Vp8(Default::default());
        let mut buf = DepacketizingBuffer::new(depack, 3);
        let meta = |seq: u64| RtpMeta {
            received: Instant::now(),
            seq_no: seq.into(),
            time: MediaTime::from_90khz(seq),
            last_sender_info: None,
            header: RtpHeader {
                sequence_number: seq as u16,
                timestamp: seq as u32,
                ..Default::default()
            },
        };

        // Start observing this PT after the head of a VP8 frame was lost.
        buf.push(meta(1), [0x00]);
        assert!(buf.pop(Instant::now(), None).is_none());

        // The sender switches PT before this depayloader has emitted anything.
        for seq in 2..=1_001 {
            buf.push_padding(meta(seq));
            assert!(buf.pop(Instant::now(), None).is_none());
        }

        assert!(
            buf.queue.len() <= buf.hold_back + 1,
            "initial incomplete VP8 frame retained {} entries after a 1,000-packet PT switch",
            buf.queue.len()
        );
    }

    fn test_meta(base: Instant, seq: u64, time: u64, received_ms: u64) -> RtpMeta {
        RtpMeta {
            received: base + Duration::from_millis(received_ms),
            time: MediaTime::from_90khz(time),
            seq_no: seq.into(),
            last_sender_info: None,
            header: RtpHeader {
                sequence_number: seq as u16,
                timestamp: time as u32,
                ..Default::default()
            },
        }
    }

    /// Repeated output/deadline polls share a scan; consuming frames retains the suffix.
    #[test]
    fn segment_cache_reuses_scans_until_packet_insertion() {
        let base = Instant::now();
        let timeout = Some(Duration::from_millis(250));
        let mut buf = DepacketizingBuffer::new(CodecDepacketizer::Boxed(Box::new(TestDepack)), 300);
        buf.push(test_meta(base, 1, 1, 0), [1, 9]);
        buf.pop(base, timeout).unwrap().unwrap();
        for seq in 3..103 {
            buf.push(test_meta(base, seq, seq, 100), [1, 9]);
        }
        let deadline = base + Duration::from_millis(350);
        assert!(
            buf.pop(base + Duration::from_millis(100), timeout)
                .is_none()
        );
        let scans = buf.segment_rebuilds;
        for _ in 0..10 {
            assert_eq!(buf.poll_timeout(timeout), Some(deadline));
            assert!(
                buf.pop(base + Duration::from_millis(100), timeout)
                    .is_none()
            );
        }
        assert_eq!(buf.segment_rebuilds, scans);
        for seq in 3..103 {
            let dep = buf.pop(deadline, timeout).unwrap().unwrap();
            assert_eq!(**dep.seq_range().start(), seq);
            assert_eq!(dep.contiguous, seq != 3);
            assert_eq!(buf.poll_timeout(timeout), None);
        }
        assert_eq!(buf.segment_rebuilds, scans);
        assert!(buf.pop(deadline, timeout).is_none());

        // An out-of-order insertion must replace a cached blocked candidate.
        buf.push(test_meta(base, 104, 104, 400), [1, 9]);
        assert!(buf.pop(deadline, timeout).is_none());
        buf.push(test_meta(base, 103, 103, 400), [1, 9]);
        for seq in [103, 104] {
            let dep = buf
                .pop(base + Duration::from_millis(400), timeout)
                .unwrap()
                .unwrap();
            assert_eq!(**dep.seq_range().start(), seq);
            assert!(dep.contiguous);
        }
        assert_eq!(buf.segment_rebuilds, scans + 2);
    }

    #[test]
    fn segment_cache_ignores_duplicate_and_old_packets() {
        let base = Instant::now();
        let timeout = Some(Duration::from_millis(250));
        let mut buf = DepacketizingBuffer::new(CodecDepacketizer::Boxed(Box::new(TestDepack)), 3);
        buf.push(test_meta(base, 1, 1, 0), [1, 9]);
        buf.pop(base, timeout).unwrap().unwrap();
        buf.push(test_meta(base, 3, 3, 100), [1, 9]);
        let deadline = base + Duration::from_millis(350);
        assert_eq!(buf.poll_timeout(timeout), Some(deadline));
        let scans = buf.segment_rebuilds;

        for seq in [3, 1, 0] {
            buf.push(test_meta(base, seq, seq, 200), [1, 9]);
            assert_eq!(buf.poll_timeout(timeout), Some(deadline));
            assert!(
                buf.pop(base + Duration::from_millis(200), timeout)
                    .is_none()
            );
            assert_eq!(buf.segment_rebuilds, scans);
        }
        let dep = buf.pop(deadline, timeout).unwrap().unwrap();
        assert_eq!(**dep.seq_range().start(), 3);
        assert!(!dep.contiguous);
        assert_eq!(buf.segment_rebuilds, scans);
    }

    #[test]
    fn segment_cache_preserves_frames_after_depacketization_error() {
        let base = Instant::now();
        let timeout = Some(Duration::from_millis(250));
        let mut buf = DepacketizingBuffer::new(crate::format::Codec::H264.into(), 3);
        for (seq, payload) in [(1, [0x7e, 0xaa]), (2, [0x61, 0xaa])] {
            let mut meta = test_meta(base, seq, seq, 0);
            meta.header.marker = true;
            buf.push(meta, payload);
        }
        assert_eq!(buf.poll_timeout(timeout), None);
        let scans = buf.segment_rebuilds;
        assert!(buf.pop(base, timeout).unwrap().is_err());
        assert_eq!(buf.poll_timeout(timeout), None);
        let dep = buf.pop(base, timeout).unwrap().unwrap();
        assert_eq!(**dep.seq_range().start(), 2);
        assert!(dep.contiguous);
        assert!(buf.pop(base, timeout).is_none());
        assert_eq!(buf.segment_rebuilds, scans);
    }

    /// Test disabled-timeout polling preserves padding cleanup after frame emission or an error.
    #[test]
    fn timeout_none_preserves_padding_cleanup_after_emit_and_error() {
        let base = Instant::now();
        for (payload, valid) in [([0x61, 0xaa], true), ([0x7e, 0xaa], false)] {
            let mut buf = DepacketizingBuffer::new(crate::format::Codec::H264.into(), 3);
            let mut meta = test_meta(base, 1, 1, 0);
            meta.header.marker = true;
            buf.push(meta, payload);
            for seq in 2..=6 {
                buf.push_padding(test_meta(base, seq, 1, 0));
            }

            assert_eq!(buf.pop(base, None).unwrap().is_ok(), valid);
            assert_eq!(buf.queue.len(), 5);
            assert_eq!(*buf.last_emitted.unwrap().0, 1);
            assert_eq!(buf.poll_timeout(None), None);
            assert_eq!(buf.queue.len(), 5);

            // Cleanup runs on the next poll, which has no frame to process.
            let scans = buf.segment_rebuilds;
            assert!(buf.pop(base, None).is_none());
            assert_eq!(buf.queue.len(), 3);
            assert_eq!(*buf.last_emitted.unwrap().0, 3);
            assert_eq!(buf.segment_rebuilds, scans);

            // Compaction invalidates indices; the next poll rebuilds exactly once.
            for _ in 0..3 {
                assert!(buf.pop(base, None).is_none());
                assert_eq!(buf.segment_rebuilds, scans + 1);
            }
        }
    }

    /// Test an unrepresentable deadline neither panics nor releases a frame early.
    #[test]
    fn timeout_deadline_beyond_instant_range_does_not_panic() {
        let base = Instant::now();
        let (mut low, mut high) = (0, u64::MAX);
        while low < high {
            let mid = low + (high - low) / 2 + 1;
            if base.checked_add(Duration::from_secs(mid)).is_some() {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        let anchor = base.checked_add(Duration::from_secs(low)).unwrap();
        let timeout = Some(Duration::from_secs(600));
        assert!(anchor.checked_add(timeout.unwrap()).is_none());

        let mut buf = DepacketizingBuffer::new(CodecDepacketizer::Boxed(Box::new(TestDepack)), 3);
        buf.push(test_meta(base, 1, 1, 0), [1, 9]);
        buf.pop(base, timeout).unwrap().unwrap();
        buf.push(test_meta(anchor, 3, 3, 0), [1, 9]);
        assert!(buf.pop(anchor, timeout).is_none());
        assert_eq!(buf.poll_timeout(timeout), None);
        assert!(buf.pop(anchor, Some(Duration::ZERO)).unwrap().is_ok());
    }

    /// Test a zero timeout does not release a candidate before its packet receipt time.
    #[test]
    fn timeout_zero_does_not_expire_before_packet_receipt() {
        let base = Instant::now();
        let mut buf = DepacketizingBuffer::new(CodecDepacketizer::Boxed(Box::new(TestDepack)), 3);
        buf.push(test_meta(base, 1, 1, 0), [1, 9]);
        buf.pop(base, None).unwrap().unwrap();
        buf.push(test_meta(base, 3, 3, 100), [1, 9]);
        assert!(buf.pop(base, Some(Duration::ZERO)).is_none());
        assert_eq!(
            buf.poll_timeout(Some(Duration::ZERO)),
            Some(base + Duration::from_millis(100))
        );
    }

    /// Test a zero timeout skips earlier fragments only after a later candidate is complete.
    #[test]
    fn timeout_zero_emits_when_later_complete_candidate_exists() {
        let depack = CodecDepacketizer::Boxed(Box::new(TestDepack));
        let mut buf = DepacketizingBuffer::new(depack, 3);
        let base = Instant::now();

        buf.push(test_meta(base, 1, 1, 0), [1, 9]);
        let dep = buf.pop(base, Some(Duration::ZERO)).unwrap().unwrap();
        assert_eq!(**dep.seq_range().start(), 1);
        assert!(dep.contiguous);

        buf.push(test_meta(base, 2, 2, 100), [1]);
        assert!(
            buf.pop(base + Duration::from_millis(100), Some(Duration::ZERO))
                .is_none()
        );

        buf.push(test_meta(base, 4, 4, 200), [1]);
        assert!(
            buf.pop(base + Duration::from_millis(200), Some(Duration::ZERO))
                .is_none()
        );
        assert_eq!(buf.poll_timeout(Some(Duration::ZERO)), None);
        buf.push(test_meta(base, 5, 4, 200), [9]);
        let dep = buf
            .pop(base + Duration::from_millis(200), Some(Duration::ZERO))
            .expect("frame emitted")
            .expect("valid frame");
        assert_eq!(**dep.seq_range().start(), 4);
        assert_eq!(**dep.seq_range().end(), 5);
        assert!(!dep.contiguous);
        assert!(buf.queue.is_empty());
        assert_eq!(buf.hold_back, 3);
        buf.push(test_meta(base, 3, 2, 300), [9]);
        assert!(
            buf.queue.is_empty(),
            "zero timeout must not allow late packets to backtrack"
        );
        assert_eq!(buf.poll_timeout(Some(Duration::ZERO)), None);
    }

    /// Test multi-packet deadlines start at the earliest receipt, not frame completion.
    #[test]
    fn timeout_uses_earliest_packet_receipt_for_multi_packet_frame() {
        for complete_ms in [200, 400] {
            let mut buf =
                DepacketizingBuffer::new(CodecDepacketizer::Boxed(Box::new(TestDepack)), 3);
            let base = Instant::now();
            let timeout = Some(Duration::from_millis(250));
            buf.push(test_meta(base, 1, 1, 0), [1, 9]);
            assert!(buf.pop(base, None).unwrap().unwrap().contiguous);

            buf.push(test_meta(base, 3, 3, 100), [1]);
            assert!(
                buf.pop(base + Duration::from_millis(complete_ms - 1), timeout)
                    .is_none()
            );
            assert_eq!(buf.poll_timeout(timeout), None);
            buf.push(test_meta(base, 4, 3, complete_ms), [9]);
            assert_eq!(
                buf.poll_timeout(timeout),
                Some(base + Duration::from_millis(350))
            );

            if complete_ms < 350 {
                assert!(
                    buf.pop(base + Duration::from_millis(349), timeout)
                        .is_none()
                );
                // Neither duplicates nor subsequent padding restart the anchor.
                buf.push(test_meta(base, 3, 3, 300), [1]);
                buf.push_padding(test_meta(base, 5, 5, 300));
                assert_eq!(
                    buf.poll_timeout(timeout),
                    Some(base + Duration::from_millis(350))
                );
            }
            let dep = buf
                .pop(base + Duration::from_millis(complete_ms.max(350)), timeout)
                .expect("complete candidate is due")
                .unwrap();
            assert_eq!((**dep.seq_range().start(), **dep.seq_range().end()), (3, 4));
            assert!(!dep.contiguous);
            assert_eq!(buf.poll_timeout(timeout), None);
        }
    }

    /// Test reordered packet receipts use the segment minimum, excluding earlier incomplete data.
    #[test]
    fn timeout_uses_earliest_receipt_with_reordered_packets() {
        for received_ms in [[100, 200, 150], [200, 100, 150], [200, 150, 100]] {
            let base = Instant::now();
            let timeout = Some(Duration::from_millis(250));
            let mut buf =
                DepacketizingBuffer::new(CodecDepacketizer::Boxed(Box::new(TestDepack)), 3);
            buf.push(test_meta(base, 1, 1, 0), [1, 9]);
            buf.pop(base, timeout).unwrap().unwrap();
            buf.push(test_meta(base, 2, 2, 25), [1]);

            let mut packets = [
                (test_meta(base, 4, 3, received_ms[0]), [1]),
                (test_meta(base, 5, 3, received_ms[1]), [2]),
                (test_meta(base, 6, 3, received_ms[2]), [9]),
            ];
            packets.sort_by_key(|(meta, _)| meta.received);
            for (meta, data) in packets {
                buf.push(meta, data);
            }

            let deadline = base + Duration::from_millis(350);
            assert_eq!(buf.poll_timeout(timeout), Some(deadline));
            assert!(
                buf.pop(deadline - Duration::from_nanos(1), timeout)
                    .is_none()
            );
            let dep = buf.pop(deadline, timeout).unwrap().unwrap();
            assert_eq!((**dep.seq_range().start(), **dep.seq_range().end()), (4, 6));
            assert_eq!(dep.data, [1, 2, 9]);
            assert_eq!(dep.first_network_time(), base + Duration::from_millis(100));
            assert!(!dep.contiguous);
            assert_eq!(buf.poll_timeout(timeout), None);
        }
    }

    /// Test a timestamp boundary excludes the next frame's earlier receipt from the segment minimum.
    #[test]
    fn timeout_segment_receipt_excludes_next_timestamp() {
        let base = Instant::now();
        let timeout = Some(Duration::from_millis(250));
        let mut buf = DepacketizingBuffer::new(CodecDepacketizer::Boxed(Box::new(TestDepack)), 3);
        buf.push(test_meta(base, 1, 1, 0), [1, 9]);
        buf.pop(base, timeout).unwrap().unwrap();

        buf.push(test_meta(base, 5, 4, 50), [1, 9]);
        assert_eq!(
            buf.poll_timeout(timeout),
            Some(base + Duration::from_millis(300))
        );
        buf.push(test_meta(base, 3, 3, 100), [1]);
        buf.push(test_meta(base, 4, 3, 150), [2]);

        let deadline = base + Duration::from_millis(350);
        assert_eq!(buf.poll_timeout(timeout), Some(deadline));
        assert!(
            buf.pop(deadline - Duration::from_nanos(1), timeout)
                .is_none()
        );
        let dep = buf.pop(deadline, timeout).unwrap().unwrap();
        assert_eq!((**dep.seq_range().start(), **dep.seq_range().end()), (3, 4));
        assert_eq!(dep.data, [1, 2]);
        assert_eq!(dep.first_network_time(), base + Duration::from_millis(100));
        assert!(!dep.contiguous);

        let next = buf.pop(deadline, timeout).unwrap().unwrap();
        assert_eq!(
            (**next.seq_range().start(), **next.seq_range().end()),
            (5, 5)
        );
        assert_eq!(next.first_network_time(), base + Duration::from_millis(50));
        assert!(next.contiguous);
        assert_eq!(buf.poll_timeout(timeout), None);
    }

    /// Test a disabled timeout keeps count-based release.
    #[test]
    fn timeout_disabled_preserves_count_release() {
        let depack = CodecDepacketizer::Boxed(Box::new(TestDepack));
        let mut buf = DepacketizingBuffer::new(depack, 3);
        let base = Instant::now();

        let timeout = None;
        buf.push(test_meta(base, 1, 1, 0), [1, 9]);
        buf.pop(base, timeout).unwrap().unwrap();
        buf.push(test_meta(base, 3, 3, 100), [1, 9]);
        assert!(
            buf.pop(base + Duration::from_millis(100), timeout)
                .is_none()
        );
        assert_eq!(buf.poll_timeout(None), None);
        assert!(buf.pop(base + Duration::from_secs(1), None).is_none());
        for seq in 4..=5 {
            buf.push(test_meta(base, seq, seq, 1000), [1, 9]);
        }
        let dep = buf
            .pop(base + Duration::from_secs(1), None)
            .unwrap()
            .unwrap();
        assert_eq!(**dep.seq_range().start(), 3);
        assert!(!dep.contiguous);
    }

    /// Test the count threshold can release a blocked frame before its deadline.
    #[test]
    fn timeout_count_limit_can_win_before_deadline() {
        let depack = CodecDepacketizer::Boxed(Box::new(TestDepack));
        let mut buf = DepacketizingBuffer::new(depack, 3);
        let base = Instant::now();

        let timeout = Some(Duration::from_secs(1));
        buf.push(test_meta(base, 1, 1, 0), [1, 9]);
        buf.pop(base, timeout).unwrap().unwrap();
        for seq in 3..=5 {
            buf.push(test_meta(base, seq, seq, 100), [1, 9]);
        }
        let dep = buf
            .pop(base + Duration::from_millis(100), timeout)
            .unwrap()
            .unwrap();
        assert_eq!(**dep.seq_range().start(), 3);
        assert!(!dep.contiguous);
    }

    /// Test codec rejection retries the next candidate only when the timeout is enabled.
    #[test]
    fn timeout_codec_rejection_makes_progress() {
        #[derive(Debug)]
        struct LayerDepack;
        impl Depacketizer for LayerDepack {
            fn out_size_hint(&self, packets_size: usize) -> Option<usize> {
                Some(packets_size)
            }
            fn depacketize(
                &mut self,
                packet: &[u8],
                out: &mut Vec<u8>,
                extra: &mut CodecExtra,
            ) -> Result<(), PacketError> {
                out.extend_from_slice(packet);
                *extra = CodecExtra::Vp8(super::super::Vp8CodecExtra {
                    picture_id: Some(packet[1].into()),
                    tl0_picture_id: Some(packet[2].into()),
                    layer_index: packet[3],
                    discardable: false,
                    sync: false,
                    is_keyframe: false,
                });
                Ok(())
            }
            fn is_partition_head(&self, packet: &[u8]) -> bool {
                TestDepack.is_partition_head(packet)
            }
            fn is_partition_tail(&self, marker: bool, packet: &[u8]) -> bool {
                TestDepack.is_partition_tail(marker, packet)
            }
        }

        for timeout in [None, Some(Duration::ZERO), Some(Duration::from_millis(250))] {
            let base = Instant::now();
            let hold_back = if timeout.is_none() { 2 } else { 30 };
            let mut buf = DepacketizingBuffer::new(
                CodecDepacketizer::Boxed(Box::new(LayerDepack)),
                hold_back,
            );
            buf.contiguity = Contiguity::Vp8(Vp8Contiguity::new());
            buf.push(test_meta(base, 1, 1, 0), [1, 1, 1, 0, 9]);
            buf.pop(base, timeout).unwrap().unwrap();
            buf.push(test_meta(base, 3, 3, 100), [1, 3, 1, 1, 9]);
            buf.push(test_meta(base, 4, 4, 100), [1, 4, 2, 0, 9]);
            let due = base + Duration::from_millis(100) + timeout.unwrap_or_default();
            if timeout.is_none() {
                for seq in 5..=9 {
                    buf.push_padding(test_meta(base, seq, seq, 100));
                }
                assert!(buf.pop(due, None).is_none());
                assert_eq!(*buf.queue.front().unwrap().meta.seq_no, 4);
                assert_eq!(buf.queue.len(), 6);
                assert_eq!(*buf.last_emitted.unwrap().0, 1);
                continue;
            }
            buf.update_segments();
            let scans = buf.segment_rebuilds;
            let dep = buf
                .pop(due, timeout)
                .expect("drain past codec-rejected frame")
                .unwrap();
            assert_eq!(**dep.seq_range().start(), 4);
            assert_eq!(
                buf.segment_rebuilds, scans,
                "codec rejection must reuse segments"
            );
            assert!(buf.queue.is_empty());
            assert_eq!(buf.poll_timeout(timeout), None);
        }
    }

    fn test(
        v: &[(
            u64,   // seq
            u64,   // time
            &[u8], // data
            &[(
                u64,   // time
                &[u8], // depacketized data
            )],
        )],
    ) {
        test_n(3, v)
    }

    fn test0(
        v: &[(
            u64,   // seq
            u64,   // time
            &[u8], // data
            &[(
                u64,   // time
                &[u8], // depacketized data
            )],
        )],
    ) {
        test_n(0, v)
    }

    fn test_n(
        hold_back: usize,
        v: &[(
            u64,   // seq
            u64,   // time
            &[u8], // data
            &[(
                u64,   // time
                &[u8], // depacketized data
            )],
        )],
    ) {
        let depack = CodecDepacketizer::Boxed(Box::new(TestDepack));
        let mut buf = DepacketizingBuffer::new(depack, hold_back);

        for (step, (seq, time, data, checks)) in (1..).zip(v.iter()) {
            let meta = RtpMeta {
                received: Instant::now(),
                seq_no: (*seq).into(),
                time: MediaTime::from_90khz(*time),
                last_sender_info: None,
                header: RtpHeader {
                    sequence_number: *seq as u16,
                    timestamp: *time as u32,
                    ..Default::default()
                },
            };

            buf.push(meta, data.to_vec());

            let mut depacks = vec![];
            while let Some(res) = buf.pop(Instant::now(), None) {
                let d = res.unwrap();
                depacks.push(d);
            }

            assert_eq!(
                depacks.len(),
                checks.len(),
                "Step {}: check count not matching {} != {}",
                step,
                depacks.len(),
                checks.len()
            );

            let iter = depacks.into_iter().zip(checks.iter());

            for (depack, (dtime, ddata)) in iter {
                assert_eq!(
                    depack.time.numer(),
                    *dtime,
                    "Step {}: Time not matching {} != {}",
                    step,
                    depack.time.numer(),
                    *dtime
                );

                assert_eq!(
                    depack.data, *ddata,
                    "Step {}: Data not correct {:?} != {:?}",
                    step, depack.data, *ddata
                );
            }
        }
    }

    #[derive(Debug)]
    struct TestDepack;

    impl Depacketizer for TestDepack {
        fn out_size_hint(&self, packets_size: usize) -> Option<usize> {
            Some(packets_size)
        }

        fn depacketize(
            &mut self,
            packet: &[u8],
            out: &mut Vec<u8>,
            _: &mut CodecExtra,
        ) -> Result<(), PacketError> {
            out.extend_from_slice(packet);
            Ok(())
        }

        fn is_partition_head(&self, packet: &[u8]) -> bool {
            !packet.is_empty() && packet[0] == 1
        }

        fn is_partition_tail(&self, _marker: bool, packet: &[u8]) -> bool {
            !packet.is_empty() && packet.contains(&9)
        }
    }

    #[test]
    fn rtp_out_of_order() {
        let construct_input =
            |(time, seq, marker, cc, data): (u32, u16, bool, u16, Vec<u8>)| -> (RtpMeta, Vec<u8>) {
                (
                    RtpMeta {
                        received: Instant::now(),
                        time: MediaTime::new(time.into(), Frequency::new(90000).unwrap()),
                        seq_no: SeqNo::from(seq as u64),
                        header: RtpHeader {
                            version: 2,
                            has_padding: false,
                            has_extension: true,
                            csrc_count: 0,
                            marker,
                            payload_type: Pt::new_with_value(98),
                            sequence_number: seq,
                            timestamp: time,
                            ssrc: Ssrc::from(2930203832),
                            csrc: [0; 15],
                            ext_vals: ExtensionValues {
                                transport_cc: Some(cc),
                                ..Default::default()
                            },
                            header_len: 28,
                        },
                        last_sender_info: None,
                    },
                    data,
                )
            };

        let inputs = [
            // PID: 23860
            (
                821395241, // Timestamp
                8685,      // SeqN
                false,     // Marker
                56,        // Transport CC
                // VP9 header--------+
                //                   |
                //        +--------------------+
                Vec::from([236, 221, 52, 80, 26, 10, 1, 1, 1, 1, 1, 1, 1, 1]), // Data
            ),
            // PID: 23860
            (
                821395241, // Timestamp
                8686,      // SeqN
                true,      // Marker
                57,        // Transport CC
                // VP9 header--------+
                //                   |
                //        +--------------------+
                Vec::from([237, 221, 52, 83, 26, 10, 2, 2, 2, 2, 2, 2, 2, 2]), // Data
            ),
            // PID: 23861
            (
                821398481, // Timestamp
                8687,      // SeqN
                false,     // Marker
                60,        // Transport CC
                // VP9 header--------+
                //                   |
                //        +------------------------+
                Vec::from([170, 221, 53, 16, 27, 56, 20, 0, 0, 0, 0, 0, 0, 0, 0]), // Data
            ),
            // PID: 23861
            (
                821398481, // Timestamp
                8688,      // SeqN
                false,     // Marker
                61,        // Transport CC
                // VP9 header--------+
                //                   |
                //        +--------------------+
                Vec::from([160, 221, 53, 16, 27, 20, 1, 1, 1, 1, 1, 1, 1, 1]), // Data
            ),
            // PID: 23861
            (
                821398481,
                8689,
                false,
                62,
                // VP9 header--------+
                //                   |
                //        +--------------------+
                Vec::from([164, 221, 53, 16, 27, 20, 2, 2, 2, 2, 2, 2, 2, 2]), // Data
            ),
            // PID: 23861
            (
                821398481, // Timestamp
                8690,      // SeqN
                false,     // Marker
                63,        // Transport CC
                // VP9 header--------+
                //                   |
                //        +--------------------+
                Vec::from([169, 221, 53, 19, 27, 20, 3, 3, 3, 3, 3, 3, 3, 3]), // Data
            ),
            // PID: 23861
            (
                821398481, // Timestamp
                8691,      // SeqN
                false,     // Marker
                64,        // Transport CC
                // VP9 header--------+
                //                   |
                //        +--------------------+
                Vec::from([161, 221, 53, 19, 27, 20, 4, 4, 4, 4, 4, 4, 4, 4]), // Data
            ),
            // PID: 23861
            (
                821398481, // Timestamp
                8692,      // SeqN
                false,     // Marker
                65,        // Transport CC
                // VP9 header--------+
                //                   |
                //        +--------------------+
                Vec::from([161, 221, 53, 19, 27, 20, 5, 5, 5, 5, 5, 5, 5, 5]), // Data
            ),
            // PID: 23861
            (
                821398481, // Timestamp
                8693,      // SeqN
                false,     // Marker
                66,        // Transport CC
                // VP9 header--------+
                //                   |
                //        +--------------------+
                Vec::from([161, 221, 53, 19, 27, 20, 6, 6, 6, 6, 6, 6, 6, 6]), // Data
            ),
            // PID: 23861
            (
                821398481, // Timestamp
                8694,      // SeqN
                true,      // Marker
                67,        // Transport CC
                // VP9 header--------+
                //                   |
                //        +--------------------+
                Vec::from([165, 221, 53, 19, 27, 20, 7, 7, 7, 7, 7, 7, 7, 7]), // Data
            ),
        ];

        let mut buffer =
            DepacketizingBuffer::new(CodecDepacketizer::Vp9(Vp9Depacketizer::default()), 30);

        for input in &inputs {
            let (meta, data) = construct_input(input.clone());
            buffer.push(meta, data);
        }

        let now = Instant::now();
        let res0before = buffer.pop(now, None).unwrap().unwrap(); // Pop PID: 23860, `contiguous_seq == true`.
        let res1before = buffer.pop(now, None).unwrap().unwrap(); // Pop PID: 23861, `contiguous_seq == true`.

        let mut buffer =
            DepacketizingBuffer::new(CodecDepacketizer::Vp9(Vp9Depacketizer::default()), 30);

        for input in &inputs {
            let (meta, data) = construct_input(input.clone());
            if meta.seq_no == SeqNo::from(8689) {
                continue; // Skip RTP packet with seq_num=8689 vp9_payload=[20, 2, 2, 2, 2, 2, 2, 2, 2].
            }
            buffer.push(meta.clone(), data.clone());
        }

        // Pop PID: 23860, `contiguous_seq == true`.
        let res0after = buffer.pop(now, None).unwrap().unwrap();
        // Try to pop PID: 23861. `None` because `contiguous_seq == false` -- no seq_num=8689.
        assert!(buffer.pop(now, None).is_none());
        assert!(buffer.pop(now, None).is_none()); // Ensure once again.

        for input in &inputs {
            let (meta, data) = construct_input(input.clone());
            if meta.seq_no == SeqNo::from(8689) {
                // Send RTP packet with seq_num=8689 vp9_payload=[20, 2, 2, 2, 2, 2, 2, 2, 2].
                buffer.push(meta.clone(), data.clone());
                break;
            }
        }

        let res1after = buffer.pop(now, None).unwrap().unwrap();

        assert_eq!(res0before.data, res0after.data);
        assert_eq!(res1before.data, res1after.data);
    }
}
