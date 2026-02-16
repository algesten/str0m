use crate::format::CodecSpec;
use crate::format::Vp9PacketizerMode;
use crate::media::ToPayload;
use crate::rtp::vla::VideoLayersAllocation;
use crate::rtp_::Frequency;
use crate::streams::StreamTx;

use super::PacketError;
use super::{CodecPacketizer, Packetizer};

#[derive(Debug)]
pub struct Payloader {
    pack: CodecPacketizer,
    clock_rate: Frequency,
}

impl Payloader {
    pub(crate) fn new(spec: CodecSpec, vp9_mode: Vp9PacketizerMode) -> Self {
        Payloader {
            pack: CodecPacketizer::new(spec.codec, vp9_mode),
            clock_rate: spec.clock_rate,
        }
    }

    pub(crate) fn push_sample(
        &mut self,
        to_payload: ToPayload,
        mtu: usize,
        is_audio: bool,
        stream: &mut StreamTx,
    ) -> Result<(), PacketError> {
        let ToPayload {
            pt,
            wallclock,
            rtp_time,
            data,
            start_of_talk_spurt,
            ext_vals,
            ..
        } = to_payload;

        let chunks = self.pack.packetize(mtu, &data)?;
        let len = chunks.len();

        for (idx, data) in chunks.into_iter().enumerate() {
            let last = idx == len - 1;
            let first = idx == 0;

            let previous_data = stream.last_packet();
            let marker = self.pack.is_marker(data.as_slice(), previous_data, last)
                || (is_audio && start_of_talk_spurt);

            let seq_no = stream.next_seq_no();

            // TODO: delegate to self.pack to decide whether this packet is nackable.
            let nackable = !is_audio;

            let mut pkt_ext_vals = ext_vals.clone();
            if !first {
                pkt_ext_vals.user_values.remove::<VideoLayersAllocation>();
            }

            stream.write_rtp(
                pt,
                seq_no,
                rtp_time.rebase(self.clock_rate).numer() as u32,
                wallclock,
                marker,
                pkt_ext_vals,
                nackable,
                data,
            )?;
        }

        Ok(())
    }
}
