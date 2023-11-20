use std::collections::HashMap;
use std::collections::{BTreeMap, VecDeque};

use std::fmt;
use std::time::{Duration, Instant};

use crate::format::CodecSpec;
use crate::media::ToPayload;
use crate::rtp_::{ExtensionValues, Frequency, MediaTime, Rid, RtpHeader, SeqNo, Ssrc};
use crate::streams::StreamTx;

use super::{CodecPacketizer, PacketError, Packetizer, QueueSnapshot};
use super::{MediaKind, QueuePriority};

#[derive(Debug)]
pub struct Payloader {
    pack: CodecPacketizer,
    clock_rate: Frequency,
}

impl Payloader {
    pub(crate) fn new(spec: CodecSpec) -> Self {
        Payloader {
            pack: spec.codec.into(),
            clock_rate: spec.clock_rate,
        }
    }

    pub(crate) fn push_sample(
        &mut self,
        now: Instant,
        to_payload: ToPayload,
        mtu: usize,
        is_audio: bool,
        stream: &mut StreamTx,
    ) -> Result<(), PacketError> {
        let ToPayload {
            pt,
            rid,
            wallclock,
            rtp_time,
            data,
            ext_vals,
        } = to_payload;

        let chunks = self.pack.packetize(mtu, &data)?;
        let len = chunks.len();

        let ssrc = stream.ssrc();

        let mut data_len = 0;

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
                rtp_time.rebase(self.clock_rate).numer() as u32,
                wallclock,
                marker,
                ext_vals.clone(),
                nackable,
                data,
            );
        }

        Ok(())
    }
}
