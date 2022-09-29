use std::collections::VecDeque;
use std::fmt;

use rtp::{MediaTime, SeqNo};

use crate::{CodecDepacketizer, Depacketizer, PacketError};

// Internal struct to hold one pushed entry of RTP data with sequence number and marker.
struct Rtp {
    data: Vec<u8>,
    time: MediaTime,
    seq_no: SeqNo,
    marker: bool,
}

#[derive(Debug)]
pub struct DepacketizingBuffer {
    depack: CodecDepacketizer,
    last_emitted: Option<SeqNo>,
    queue: VecDeque<Rtp>,
}

impl DepacketizingBuffer {
    pub fn new(depack: CodecDepacketizer) -> Self {
        DepacketizingBuffer {
            depack,
            last_emitted: None,
            queue: VecDeque::new(),
        }
    }

    pub fn push(&mut self, data: Vec<u8>, time: MediaTime, seq_no: SeqNo, marker: bool) {
        // We're not emitting samples in the wrong order. If we receive
        // packets that are before the last emitted, we drop.
        if let Some(last_emitted) = self.last_emitted {
            if seq_no <= last_emitted {
                trace!("Drop packet before emitted: {} <= {}", seq_no, last_emitted);
                return;
            }
        }

        match self.queue.binary_search_by_key(&seq_no, |r| r.seq_no) {
            Ok(_) => {
                // exact same seq_no found. ignore
                trace!("Drop exactly same packet: {}", seq_no);
                return;
            }
            Err(i) => {
                // i is insertion point to maintain order
                self.queue.insert(
                    i,
                    Rtp {
                        data,
                        time,
                        seq_no,
                        marker,
                    },
                );
            }
        }
    }

    pub fn emit_sample(&mut self) -> Option<Result<(MediaTime, Vec<u8>), PacketError>> {
        let (start, stop) = self.find_contiguous()?;

        let mut out = Vec::new();

        let time = self.queue.get(start).expect("first index exist").time;

        for rtp in self.queue.drain(start..=stop) {
            if let Err(e) = self.depack.depacketize(&rtp.data, &mut out) {
                return Some(Err(e));
            }
            self.last_emitted = Some(rtp.seq_no);
        }

        // Clean out stuff that is now too old.
        let last = self.last_emitted.expect("there to be a last emitted");
        self.queue.retain(|r| r.seq_no > last);

        Some(Ok((time, out)))
    }

    fn find_contiguous(&self) -> Option<(usize, usize)> {
        let mut start = None;
        let mut offset = 0;
        let mut stop = None;

        for (index, rtp) in self.queue.iter().enumerate() {
            // We are not emitting older samples.
            if let Some(last) = self.last_emitted {
                if rtp.seq_no <= last {
                    continue;
                }
            }

            let index = index as i64;
            let iseq = *rtp.seq_no as i64;

            if self.depack.is_partition_head(&rtp.data) {
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

            if self.depack.is_partition_tail(rtp.marker, &rtp.data) {
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

impl fmt::Debug for Rtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rtp")
            .field("seq_no", &self.seq_no)
            .field("marker", &self.marker)
            .field("len", &self.data.len())
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Chrome sends padding packets in between real RTP frames. A bit unclear why.
    #[test]
    fn padded_frame() {
        let mut buf =
            DepacketizingBuffer::new(CodecDepacketizer::Boxed(Box::new(TestDepacketizer)));

        let t1 = MediaTime::new(0, 90_000);
        buf.push(vec![1], t1, 0.into(), false);
        buf.push(vec![2], t1, 1.into(), false);
        buf.push(vec![3], t1, 2.into(), true);

        // padding packet for same time t1 here.
        buf.push(vec![], t1, 3.into(), false);

        let t2 = MediaTime::new(1500, 90_000);
        buf.push(vec![4], t2, 4.into(), false);
        buf.push(vec![5], t2, 5.into(), false);
        buf.push(vec![6], t2, 6.into(), true);

        buf.push(vec![], t2, 7.into(), false);

        let (rt1, d1) = buf.emit_sample().expect("sample 1").unwrap();
        let (rt2, d2) = buf.emit_sample().expect("sample 2").unwrap();
        assert_eq!(rt1, t1);
        assert_eq!(rt2, t2);
        assert_eq!(d1, vec![1, 2, 3]);
        assert_eq!(d2, vec![4, 5, 6]);
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
