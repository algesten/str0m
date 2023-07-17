use std::collections::HashMap;
use std::collections::{BTreeMap, VecDeque};

use std::fmt;
use std::time::{Duration, Instant};

use crate::media::ToPacketize;
use crate::rtp_::{ExtensionValues, MediaTime, Rid, RtpHeader, SeqNo, Ssrc};
use crate::streams::StreamTx;

use super::ring::Ident;
use super::ring::RingBuf;
use super::{CodecPacketizer, PacketError, Packetizer, QueueSnapshot};
use super::{MediaKind, QueuePriority};

#[derive(PartialEq, Eq)]
pub struct Packetized {
    pub data: Vec<u8>,
    pub first: bool,
    pub marker: bool,
    pub meta: PacketizedMeta,
    pub queued_at: Instant,

    /// Set when packet is first sent. This is so we can resend.
    pub seq_no: Option<SeqNo>,
    /// Whether this packetized is counted towards the TotalQueue
    pub count_as_unsent: bool,

    /// If we are in rtp_mode, this is the original incoming header.
    pub rtp_mode_header: Option<RtpHeader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketizedMeta {
    pub rtp_time: MediaTime,
    pub ssrc: Ssrc,
    pub rid: Option<Rid>,
    pub ext_vals: ExtensionValues,
}

#[derive(Debug)]
pub struct PacketizingBuffer {
    pack: CodecPacketizer,
    by_seq: HashMap<SeqNo, Ident>,
    by_size: BTreeMap<usize, Ident>,

    emit_next: Ident,
    last_emit: Option<Instant>,
    max_retain: usize,

    // Set when we first discover the SSRC
    ssrc: Option<Ssrc>,
}

const SIZE_BUCKET: usize = 25;

impl PacketizingBuffer {
    pub(crate) fn new(pack: CodecPacketizer, max_retain: usize) -> Self {
        PacketizingBuffer {
            pack,
            by_seq: HashMap::new(),
            by_size: BTreeMap::new(),

            emit_next: Ident::default(),
            last_emit: None,
            max_retain,

            ssrc: None,
        }
    }

    pub(crate) fn push_sample(
        &mut self,
        now: Instant,
        to_packetize: ToPacketize,
        mtu: usize,
        is_audio: bool,
        stream: &mut StreamTx,
    ) -> Result<(), PacketError> {
        let ToPacketize {
            pt,
            rid,
            wallclock,
            rtp_time,
            data,
            ext_vals,
            max_retain,
        } = to_packetize;

        let chunks = self.pack.packetize(mtu, &data)?;
        let len = chunks.len();

        let ssrc = stream.ssrc();

        assert!(
            len <= self.max_retain,
            "Data larger than send buffer {} > {}",
            data.len(),
            self.max_retain
        );

        let mut data_len = 0;

        if self.ssrc.is_none() {
            self.ssrc = Some(ssrc);
        }

        for (idx, data) in chunks.into_iter().enumerate() {
            let first = idx == 0;
            let last = idx == len - 1;

            let previous_data = stream.last_packet();
            let marker = self.pack.is_marker(data.as_slice(), previous_data, last);

            data_len += data.len();

            let seq_no = stream.next_seq_no();

            // TODO: delegate to self.pack to decide whether this packet is nackable.
            let nackable = !is_audio;

            stream.write_rtp(
                pt,
                seq_no,
                rtp_time.numer() as u32,
                wallclock,
                marker,
                ext_vals,
                nackable,
                data,
            );
        }

        Ok(())
    }
}

impl fmt::Debug for Packetized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packetized")
            .field("rtp_time", &self.meta.rtp_time)
            .field("len", &self.data.len())
            .field("first", &self.first)
            .field("last", &self.marker)
            .field("ssrc", &self.meta.ssrc)
            .field("seq_no", &self.seq_no)
            .finish()
    }
}
