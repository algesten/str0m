use std::collections::VecDeque;
use std::fmt;
use std::time::Instant;

use crate::rtp::{MediaTime, RtpHeader, SeqNo};

use super::{CodecDepacketizer, CodecExtra, Depacketizer, PacketError};

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
}

#[derive(Clone)]
pub struct Depacketized {
    pub time: MediaTime,
    pub contiguous: bool,
    pub meta: Vec<RtpMeta>,
    pub data: Vec<u8>,
    pub codec_extra: CodecExtra,
}

#[derive(Debug)]
struct Entry {
    meta: RtpMeta,
    data: Vec<u8>,
    head: bool,
    tail: bool,
}

impl RtpMeta {
    #[doc(hidden)]
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
    queue: VecDeque<Entry>,
    segments: Vec<(usize, usize)>,
    last_emitted: Option<SeqNo>,
}

impl DepacketizingBuffer {
    pub fn new(depack: CodecDepacketizer, hold_back: usize) -> Self {
        DepacketizingBuffer {
            hold_back,
            depack,
            queue: VecDeque::new(),
            segments: Vec::with_capacity(hold_back),
            last_emitted: None,
        }
    }

    pub fn push(&mut self, meta: RtpMeta, data: Vec<u8>) {
        // We're not emitting samples in the wrong order. If we receive
        // packets that are before the last emitted, we drop.
        if let Some(last) = self.last_emitted {
            if meta.seq_no <= last {
                trace!("Drop before emitted: {} <= {}", meta.seq_no, last);
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

        let (start, stop) = self.segments.first()?;

        let contiguous = self.is_following_last(*start);
        let is_more_than_hold_back = self.segments.len() >= self.hold_back;

        // We prefer to just release samples because they are following the last emitted.
        // However as fallback, we "hold back" samples to let RTX mechanics fill in potential
        // gaps in the RTP sequences before letting go.
        if !contiguous && !is_more_than_hold_back {
            return None;
        }

        let mut data = Vec::new();
        let mut codec_extra = CodecExtra::None;

        let time = self.queue.get(*start).expect("first index exist").meta.time;
        let mut meta = Vec::with_capacity(stop - start + 1);

        for entry in self.queue.range_mut(*start..=*stop) {
            if let Err(e) = self
                .depack
                .depacketize(&entry.data, &mut data, &mut codec_extra)
            {
                return Some(Err(e));
            }
            meta.push(entry.meta.clone());
        }

        let last = self.queue.get(*stop).expect("entry for stop index");
        self.last_emitted = Some(last.meta.seq_no);

        // We're not going to emit samples in the incorrect order, there's no point in keeping
        // stuff before the emitted range.
        self.queue.drain(0..=*stop);

        let dep = Depacketized {
            time,
            contiguous,
            meta,
            data,
            codec_extra,
        };
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
        let Some(last) = self.last_emitted else {
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
    use super::*;
    use crate::rtp::MediaTime;

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
        let depack = CodecDepacketizer::Boxed(Box::new(TestDepack));
        let mut buf = DepacketizingBuffer::new(depack, 3);

        let mut step = 1;

        for (seq, time, data, checks) in v {
            let meta = RtpMeta {
                received: Instant::now(),
                seq_no: (*seq).into(),
                time: MediaTime::new(*time, 90_000),
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
}
