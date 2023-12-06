use core::panic;
use std::collections::VecDeque;
use std::fmt;
use std::ops::{Range, RangeInclusive};
use std::time::Instant;

use crate::rtp_::{ExtensionValues, MediaTime, RtpHeader, SenderInfo, SeqNo};

use super::vp8_contiguity::Vp8Contiguity;
use super::{CodecDepacketizer, CodecExtra, Depacketizer, PacketError, Vp8CodecExtra};

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
        let first = self.meta[0].seq_no;
        let last = self.meta.last().expect("at least one element").seq_no;
        first..=last
    }

    pub fn ext_vals(&self) -> &ExtensionValues {
        // We use the extensions from the last packet because certain extensions, such as video
        // orientation, are only added on the last packet to save bytes.
        &self.meta[self.meta.len() - 1].header.ext_vals
    }
}

#[derive(Debug)]
struct Entry {
    meta: RtpMeta,
    data: Vec<u8>,
    head: bool,
    tail: bool,
}

#[derive(Debug)]
pub struct DepacketizingBuffer {
    hold_back: usize,
    depack: CodecDepacketizer,
    queue: VecDeque<Entry>,
    segments: Vec<(usize, usize)>,
    last_emitted: Option<(SeqNo, CodecExtra)>,
    max_time: Option<MediaTime>,
    depack_cache: Option<(Range<usize>, Depacketized)>,
    vp8_contiguity: Vp8Contiguity,
}

impl DepacketizingBuffer {
    pub(crate) fn new(depack: CodecDepacketizer, hold_back: usize) -> Self {
        DepacketizingBuffer {
            hold_back,
            depack,
            queue: VecDeque::new(),
            segments: Vec::new(),
            last_emitted: None,
            max_time: None,
            depack_cache: None,
            vp8_contiguity: Vp8Contiguity::new(),
        }
    }

    pub fn push(&mut self, meta: RtpMeta, data: Vec<u8>) {
        // We're not emitting samples in the wrong order. If we receive
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
            Err(i) => {
                let head = self.depack.is_partition_head(&data);
                let tail = self.depack.is_partition_tail(meta.header.marker, &data);

                // i is insertion point to maintain order
                let entry = Entry {
                    meta,
                    data,
                    head,
                    tail,
                };
                self.queue.insert(i, entry);
            }
        }
    }

    pub fn pop(&mut self) -> Option<Result<Depacketized, PacketError>> {
        self.update_segments();

        // println!(
        //     "{:?} {:?}",
        //     self.queue.iter().map(|e| e.meta.seq_no).collect::<Vec<_>>(),
        //     self.segments
        // );

        let (start, stop) = *self.segments.first()?;

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
                self.queue.drain(0..=stop);
                return Some(Err(e));
            }
        };

        // If we have contiguity of seq numbers we emit right away,
        // Otherwise, we wait for retransmissions up to `hold_back` frames
        // and re-evaluate contiguity based on codec specific information

        let more_than_hold_back = self.segments.len() >= self.hold_back;
        let contiguous_seq = self.is_following_last(start);
        let wait_for_contiguity = !contiguous_seq && !more_than_hold_back;

        if wait_for_contiguity {
            // if we are not sending, cache the depacked
            self.depack_cache = Some((start..stop, dep));
            return None;
        }

        let (can_emit, contiguous_codec) = match dep.codec_extra {
            CodecExtra::Vp8(next) => self.vp8_contiguity.check(&next, contiguous_seq),
            CodecExtra::Vp9(_) => (true, contiguous_seq),
            CodecExtra::None => (true, contiguous_seq),
        };

        dep.contiguous = contiguous_codec;

        let last = self
            .queue
            .get(stop)
            .expect("entry for stop index")
            .meta
            .seq_no;

        // We're not going to emit samples in the incorrect order, there's no point in keeping
        // stuff before the emitted range.
        self.queue.drain(0..=stop);

        if !can_emit {
            return None;
        }

        self.last_emitted = Some((last, dep.codec_extra));

        Some(Ok(dep))
    }

    fn depacketize(
        &mut self,
        start: usize,
        stop: usize,
        seq: SeqNo,
    ) -> Result<Depacketized, PacketError> {
        if let Some(cached) = self.depack_cache.take() {
            if cached.0 == (start..stop) {
                trace!("depack cache hit for segment start {}", start);
                return Ok(cached.1);
            }
        }

        let mut data = Vec::new();
        let mut codec_extra = CodecExtra::None;

        let time = self.queue.get(start).expect("first index exist").meta.time;
        let mut meta = Vec::with_capacity(stop - start + 1);

        for entry in self.queue.range_mut(start..=stop) {
            if let Err(e) = self
                .depack
                .depacketize(&entry.data, &mut data, &mut codec_extra)
            {
                println!("depacketize error: {} {}", start, stop);
                return Err(e);
            }
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

    fn update_segments(&mut self) -> Option<(usize, usize)> {
        self.segments.clear();

        #[derive(Clone, Copy)]
        struct Start {
            index: i64,
            time: MediaTime,
            offset: i64,
        }

        let mut start: Option<Start> = None;

        for (index, entry) in self.queue.iter().enumerate() {
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
            if start.is_none() && entry.head {
                start = Some(Start {
                    index,
                    time: entry.meta.time,
                    offset: iseq - index,
                });
            }

            if start.is_some() && entry.tail {
                // We found a contiguous sequence of packets ending with something from
                // the packet (like the RTP marker bit) indicating it's the tail.
                let segment = (start.unwrap().index as usize, index as usize);
                self.segments.push(segment);
                start = None;
            }
        }

        None
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

    pub fn max_time(&self) -> Option<MediaTime> {
        self.max_time
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
    use super::*;
    use crate::{
        packet::vp9::Vp9Depacketizer,
        rtp_::{Frequency, MediaTime, Pt, Ssrc},
    };

    #[test]
    fn end_on_marker() {
        test(&[
            //
            (1, 1, &[1], &[]),
            (2, 1, &[9], &[(1, &[1, 9])]),
        ])
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

    fn test(
        v: &[(
            u64,   // seq
            i64,   // time
            &[u8], // data
            &[(
                i64,   // time
                &[u8], // depacketized data
            )],
        )],
    ) {
        test_n(3, v)
    }

    fn test0(
        v: &[(
            u64,   // seq
            i64,   // time
            &[u8], // data
            &[(
                i64,   // time
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
            i64,   // time
            &[u8], // data
            &[(
                i64,   // time
                &[u8], // depacketized data
            )],
        )],
    ) {
        let depack = CodecDepacketizer::Boxed(Box::new(TestDepack));
        let mut buf = DepacketizingBuffer::new(depack, hold_back);

        let mut step = 1;

        for (seq, time, data, checks) in v {
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
            while let Some(res) = buf.pop() {
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

            step += 1;
        }
    }

    #[derive(Debug)]
    struct TestDepack;

    impl Depacketizer for TestDepack {
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
            !packet.is_empty() && packet.iter().any(|v| *v == 9)
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
                            marker,
                            payload_type: Pt::new_with_value(98),
                            sequence_number: seq,
                            timestamp: time,
                            ssrc: Ssrc::from(2930203832),
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
            /// PID: 23860
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
            /// PID: 23860
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
            /// PID: 23861
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
            /// PID: 23861
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
            /// PID: 23861
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
            /// PID: 23861
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
            /// PID: 23861
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
            /// PID: 23861
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
            /// PID: 23861
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
            /// PID: 23861
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

        let res0before = buffer.pop().unwrap().unwrap(); // Pop PID: 23860, `contiguous_seq == true`.
        let res1before = buffer.pop().unwrap().unwrap(); // Pop PID: 23861, `contiguous_seq == true`.

        let mut buffer =
            DepacketizingBuffer::new(CodecDepacketizer::Vp9(Vp9Depacketizer::default()), 30);

        for input in &inputs {
            let (meta, data) = construct_input(input.clone());
            if meta.seq_no == SeqNo::from(8689) {
                continue; // Skip RTP packet with seq_num=8689 vp9_payload=[20, 2, 2, 2, 2, 2, 2, 2, 2].
            }
            buffer.push(meta.clone(), data.clone());
        }

        let res0after = buffer.pop().unwrap().unwrap(); // Pop PID: 23860, `contiguous_seq == true`.
        assert!(buffer.pop().is_none()); // Try to pop PID: 23861. `None` because `contiguous_seq == false` -- no seq_num=8689.
        assert!(buffer.pop().is_none()); // Ensure once again.

        for input in &inputs {
            let (meta, data) = construct_input(input.clone());
            if meta.seq_no == SeqNo::from(8689) {
                buffer.push(meta.clone(), data.clone()); // Send RTP packet with seq_num=8689 vp9_payload=[20, 2, 2, 2, 2, 2, 2, 2, 2].
                break;
            }
        }

        let res1after = buffer.pop().unwrap().unwrap();

        assert_eq!(res0before.data, res0after.data);
        assert_eq!(res1before.data, res1after.data);
    }
}
