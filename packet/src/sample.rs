use std::collections::VecDeque;

use rtp::SeqNo;

use crate::{CodecDepacketizer, Depacketizer, PacketError};

// Internal struct to hold one pushed entry of RTP data with sequence number and marker.
struct Rtp {
    data: Vec<u8>,
    seq_no: SeqNo,
    marker: bool,
}

pub struct SampleBuf {
    depack: CodecDepacketizer,
    last_emitted: Option<SeqNo>,
    queue: VecDeque<Rtp>,
}

impl SampleBuf {
    pub fn new(depack: CodecDepacketizer) -> Self {
        SampleBuf {
            depack,
            last_emitted: None,
            queue: VecDeque::new(),
        }
    }

    pub fn push(&mut self, data: Vec<u8>, seq_no: SeqNo, marker: bool) {
        // We're not emit samples in the wrong order. If we receive
        // packets that are before the last emitted, we drop.
        if let Some(last_emitted) = self.last_emitted {
            if seq_no <= last_emitted {
                return;
            }
        }

        match self.queue.binary_search_by_key(&seq_no, |r| r.seq_no) {
            Ok(_) => {
                // exact same seq_no found. ignore
                return;
            }
            Err(i) => {
                // i is insertion point to maintain order
                self.queue.insert(
                    i,
                    Rtp {
                        data,
                        seq_no,
                        marker,
                    },
                );
            }
        }
    }

    pub fn emit_sample(&mut self) -> Result<Option<Vec<u8>>, PacketError> {
        let (start, stop) = match self.find_contiguous() {
            Some((a, b)) => (a, b),
            None => return Ok(None),
        };

        let mut out = Vec::new();

        for i in start..=stop {
            let rtp = self.queue.remove(i).expect("contiguous index to exist");
            self.depack.depacketize(&rtp.data, &mut out)?;
            self.last_emitted = Some(rtp.seq_no);
        }

        // Clean out stuff that is now too old.
        let last = self.last_emitted.expect("there to be a last emitted");
        self.queue.retain(|r| r.seq_no > last);

        Ok(Some(out))
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
                    if iseq + offset != index {
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
