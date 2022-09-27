use std::collections::VecDeque;
use std::fmt;

use rtp::{MediaTime, SeqNo, Ssrc};

use crate::{CodecPacketizer, PacketError, Packetizer};

pub struct Packetized {
    pub ts: MediaTime,
    pub data: Vec<u8>,
    pub first: bool,
    pub last: bool,
    pub ssrc: Ssrc,
    pub sim_lvl: usize,

    /// Set when packet is first sent. This is so we can resend.
    pub seq_no: Option<SeqNo>,
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
        ssrc: Ssrc,
        sim_lvl: usize,
        mtu: usize,
    ) -> Result<(), PacketError> {
        let chunks = self.pack.packetize(mtu, data)?;
        let len = chunks.len();

        assert!(len <= self.max_retain, "Must retain at least chunked count");

        for (idx, data) in chunks.into_iter().enumerate() {
            let first = idx == 0;
            let last = idx == len - 1;

            let rtp = Packetized {
                ts,
                data,
                first,
                last,
                ssrc,
                sim_lvl,
                seq_no: None,
            };

            self.queue.push_back(rtp);
        }

        // Scale back retained count to max_retain
        while self.queue.len() > self.max_retain {
            self.queue.pop_front();
            self.emit_next -= 1;
        }

        Ok(())
    }

    pub fn poll_next(&mut self) -> Option<&mut Packetized> {
        let next = self.queue.get_mut(self.emit_next)?;
        self.emit_next += 1;
        Some(next)
    }

    pub fn get(&self, seq_no: SeqNo) -> Option<&Packetized> {
        self.queue.iter().find(|r| r.seq_no == Some(seq_no))
    }

    pub fn has_ssrc(&self, ssrc: Ssrc) -> bool {
        self.queue.front().map(|p| p.ssrc == ssrc).unwrap_or(false)
    }

    pub fn first_seq_no(&self) -> Option<SeqNo> {
        self.queue.front().and_then(|p| p.seq_no)
    }

    pub fn free(&self) -> usize {
        self.max_retain - self.queue.len() + self.emit_next
    }
}

impl fmt::Debug for Packetized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packetized")
            .field("ts", &self.ts)
            .field("len", &self.data.len())
            .field("first", &self.first)
            .field("last", &self.last)
            .field("ssrc", &self.ssrc)
            .field("sim_lvl", &self.sim_lvl)
            .field("seq_no", &self.seq_no)
            .finish()
    }
}
