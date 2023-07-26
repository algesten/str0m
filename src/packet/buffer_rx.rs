use std::collections::VecDeque;
use std::fmt;
use std::ops::RangeInclusive;
use std::time::Instant;

use crate::rtp_::{ExtensionValues, MediaTime, RtpHeader, SeqNo};

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

impl Depacketized {
    pub fn first_network_time(&self) -> Instant {
        self.meta
            .iter()
            .map(|m| m.received)
            .min()
            .expect("a depacketized to consist of at least one packet")
    }

    pub fn seq_range(&self) -> RangeInclusive<SeqNo> {
        let first = self.meta[0].seq_no;
        let last = self.meta.last().expect("at least one element").seq_no;
        first..=last
    }

    pub fn ext_vals(&self) -> ExtensionValues {
        // We use the extensions from the last packet because certain extensions, such as video
        // orientation, are only added on the last packet to save bytes.
        self.meta[self.meta.len() - 1].header.ext_vals
    }
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
pub struct BufEntry {
    meta: RtpMeta,
    data: Vec<u8>,
}
#[derive(Debug)]
pub struct JitterBuffer {
    // TODO: figure out what hold_back means for the jitter buffer
    // - is it the max number of rtp packets held in here ?
    // - how does it play nicely with the hold_back in the depayloader ?
    // - also: jitterbuffer is created within StreamRx, which is in turn created
    // in a number of places (with `expect_stream_rx`) and in those places we
    // may not have clear knowledge of the desired hold_back value
    // hold_back: usize,
    queue: VecDeque<BufEntry>,
    max_time: Option<MediaTime>,
}

impl JitterBuffer {
    pub fn new(// hold_back: usize
    ) -> Self {
        JitterBuffer {
            // hold_back,
            queue: VecDeque::new(),
            max_time: None,
        }
    }

    pub fn push(&mut self, meta: RtpMeta, data: Vec<u8>) {
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
                // i is insertion point to maintain order
                let entry = BufEntry { meta, data };
                self.queue.insert(i, entry);
            }
        }
    }

    pub fn view(&mut self) -> &[BufEntry] {
        self.queue.make_contiguous();
        self.queue.as_slices().0
    }

    pub fn remove(&mut self, n: usize) {
        self.queue.drain(0..=n);
    }
}

pub struct Depayloader {
    // number of samples
    hold_back: usize,
    // depacketizer
    depack: CodecDepacketizer,
    // segments detected in the last buf slice
    segments: Vec<(usize, usize)>,
    // the sequence number and codec specific information of the last sample depacketized
    last_emitted: Option<(SeqNo, CodecExtra)>,
    // last emitted sample
    depack_cache: Option<(SeqNo, Depacketized)>,
}

impl Depayloader {
    pub(crate) fn new(depack: CodecDepacketizer, hold_back: usize) -> Self {
        Depayloader {
            depack,
            hold_back,
            segments: Vec::new(),
            last_emitted: None,
            depack_cache: None,
        }
    }

    /// Attempts to pop a Depacketized out of the given buffer slice.  Returns
    /// the number of entries consumed so thay can be removed from the buffer as
    /// well as the Result<Depacketized, PacketError>.
    pub fn depayload(
        &mut self,
        buf: &[BufEntry],
    ) -> Option<(usize, Result<Depacketized, PacketError>)> {
        self.update_segments(buf);

        // println!(
        //     "{:?} {:?}",
        //     self.queue.iter().map(|e| e.meta.seq_no).collect::<Vec<_>>(),
        //     self.segments
        // );

        let (start, stop) = *self.segments.first()?;

        let seq = {
            let last = buf.get(stop).expect("entry for stop index");
            last.meta.seq_no
        };

        // depack ahead to check contiguity, even if we may not emit right away
        let dep = match self.depack(start, stop, seq, buf) {
            Ok(d) => d,
            Err(e) => {
                // this segment cannot be decoded correctly
                // remove from the queue and return the error
                self.last_emitted = Some((seq, CodecExtra::None));
                return Some((stop, Err(e)));
            }
        };

        let contiguous = self.contiguous(start, stop, &dep, buf);

        let is_more_than_hold_back = self.segments.len() >= self.hold_back;

        // We prefer to just release samples because they are following the last emitted.
        // However as fallback, we "hold back" samples to let RTX mechanics fill in potential
        // gaps in the RTP sequences before letting go.
        if !contiguous && !is_more_than_hold_back {
            // if we are not sending it, cache the depacked
            self.depack_cache = Some((seq, dep));
            return None;
        }

        let last = buf.get(stop).expect("entry for stop index");
        self.last_emitted = Some((last.meta.seq_no, dep.codec_extra));

        Some((stop, Ok(dep)))
    }

    fn update_segments(&mut self, buf: &[BufEntry]) -> Option<(usize, usize)> {
        self.segments.clear();

        #[derive(Clone, Copy)]
        struct Start {
            index: i64,
            time: MediaTime,
            offset: i64,
        }

        let mut start: Option<Start> = None;

        for (index, entry) in buf.iter().enumerate() {
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
            let head = self.depack.is_partition_head(&entry.data);
            let tail = self
                .depack
                .is_partition_tail(entry.meta.header.marker, &entry.data);
            if start.is_none() && head {
                start = Some(Start {
                    index,
                    time: entry.meta.time,
                    offset: iseq - index,
                });
            }

            if start.is_some() && tail {
                // We found a contiguous sequence of packets ending with something from
                // the packet (like the RTP marker bit) indicating it's the tail.
                let segment = (start.unwrap().index as usize, index as usize);
                self.segments.push(segment);
                start = None;
            }
        }

        None
    }

    fn is_following_last(&self, start: usize, buf: &[BufEntry]) -> bool {
        let Some((last, _)) = self.last_emitted else {
            // First time we emit something.
            return true;
        };

        // track sequence numbers are sequential
        let mut seq = last;

        // Expect all entries before start to be padding.
        for entry in buf[0..start].iter() {
            if !seq.is_next(entry.meta.seq_no) {
                // Not a sequence
                return false;
            }
            // for next loop round.
            seq = entry.meta.seq_no;

            let head = self.depack.is_partition_head(&entry.data);
            let tail = self
                .depack
                .is_partition_tail(entry.meta.header.marker, &entry.data);
            let is_padding = entry.data.is_empty() && !head && !tail;
            if !is_padding {
                return false;
            }
        }

        let start_entry = buf.get(start).expect("entry for start index");

        seq.is_next(start_entry.meta.seq_no)
    }

    fn contiguous(&self, start: usize, stop: usize, dep: &Depacketized, buf: &[BufEntry]) -> bool {
        if self.is_following_last(start, buf) {
            return true;
        }

        let Some((last_seq, last_codec_extra)) = self.last_emitted else {
            return true;
        };

        match (last_codec_extra, dep.codec_extra) {
            (CodecExtra::Vp8(prev), CodecExtra::Vp8(next)) => {
                // In the case of VP8 chrome doesn't answer nacks for frames that are on
                // temporal layer1 Since VP8 frames are interleaved, we can tolerate a
                // missing frame on layer 1 that its contiguous to two frames on layer 0

                let Some(prev_pid) = prev.picture_id else {
                        return false;
                    };
                let Some(next_pid) = next.picture_id else {
                        return false;
                    };

                let allowed =
                    prev.layer_index == 0 && next.layer_index == 0 && (prev_pid + 2 == next_pid);

                if allowed {
                    let last = buf.get(stop).expect("entry for stop index");
                    trace!(
                        "Depack gap allowed for Seq: {} - {}, PIDs: {} - {}",
                        last_seq,
                        last.meta.seq_no,
                        prev_pid,
                        next_pid
                    );
                }

                allowed
            }
            _ => false,
        }
    }

    fn depack(
        &mut self,
        start: usize,
        stop: usize,
        seq: SeqNo,
        buf: &[BufEntry],
    ) -> Result<Depacketized, PacketError> {
        if let Some(cached) = self.depack_cache.take() {
            if cached.0 == seq {
                trace!("depack cache hit for segment start {}", start);
                return Ok(cached.1);
            }
        }

        let mut data = Vec::new();
        let mut codec_extra = CodecExtra::None;

        let time = buf.get(start).expect("first index exist").meta.time;
        let mut meta = Vec::with_capacity(stop - start + 1);

        for entry in buf[start..=stop].iter() {
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
    use crate::rtp_::MediaTime;

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
