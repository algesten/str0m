use std::collections::VecDeque;

use rtp::{MediaTime, SeqNo};

use crate::{CodecPacketizer, PacketError, Packetizer};

pub struct Packetized {
    pub ts: MediaTime,
    pub seq_no: SeqNo,
    pub data: Vec<u8>,
    pub first: bool,
    pub last: bool,
}

pub struct PacketizingBuffer {
    pack: CodecPacketizer,
    queue: VecDeque<Packetized>,
    emit_next: usize,
    max_retain: usize,
}

impl PacketizingBuffer {
    pub fn new(pack: CodecPacketizer, max_retain: usize) -> Self {
        PacketizingBuffer {
            pack,
            queue: VecDeque::new(),
            emit_next: 0,
            max_retain,
        }
    }

    pub fn push_sample(
        &mut self,
        ts: MediaTime,
        data: &[u8],
        seq_no: SeqNo,
        mtu: usize,
    ) -> Result<SeqNo, PacketError> {
        let chunks = self.pack.packetize(mtu, data)?;
        let len = chunks.len();

        assert!(len <= self.max_retain, "Must retain at least chunked count");

        let mut cur = *seq_no;

        for (idx, data) in chunks.into_iter().enumerate() {
            let seq_no = cur.into();
            cur += 1;

            let first = idx == 0;
            let last = idx == len - 1;

            let rtp = Packetized {
                ts,
                seq_no,
                data,
                first,
                last,
            };

            self.queue.push_back(rtp);
        }

        // Scale back retained count to max_retain
        while self.queue.len() > self.max_retain {
            self.queue.pop_front();
            self.emit_next -= 1;
        }

        Ok(cur.into())
    }

    pub fn poll_next(&mut self) -> Option<&Packetized> {
        let next = self.queue.get(self.emit_next)?;
        self.emit_next += 1;
        Some(next)
    }

    pub fn get(&self, seq_no: SeqNo) -> Option<&Packetized> {
        self.queue.iter().find(|r| r.seq_no == seq_no)
    }
}
