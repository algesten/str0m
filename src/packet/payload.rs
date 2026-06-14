use crate::format::CodecSpec;
use crate::format::Vp9PacketizerMode;
use crate::media::ToPayload;
use crate::rtp::vla::VideoLayersAllocation;
use crate::rtp_::{Frequency, Pt};
use crate::streams::{RtpWrite, StreamTx};

use super::PacketError;
use super::{CodecPacketizer, Packetizer, RedEncoder, RedundantBlock};

#[derive(Debug)]
pub struct Payloader {
    pack: CodecPacketizer,
    clock_rate: Frequency,
    red: Option<RedState>,
}

/// Send-side RFC 2198 RED state: one level of redundancy carrying the previous payload.
#[derive(Debug)]
struct RedState {
    red_pt: Pt,
    primary_pt: Pt,
    /// Previous packet's `(payload, rtp_time)`, used as the redundant block.
    history: Option<(Vec<u8>, u32)>,
}

impl RedState {
    /// Wrap the primary `payload` (at `rtp_time`) into a RED payload, prepending the previous
    /// payload as one level of redundancy when it fits RFC 2198's field limits. Updates history.
    fn wrap(&mut self, payload: Vec<u8>, rtp_time: u32) -> Vec<u8> {
        let primary_pt = *self.primary_pt;
        let redundant: Vec<RedundantBlock> = self
            .history
            .as_ref()
            .and_then(|(prev, prev_time)| {
                let block = RedundantBlock {
                    pt: primary_pt,
                    timestamp_offset: rtp_time.wrapping_sub(*prev_time),
                    payload: prev.clone(),
                };
                block.fits().then_some(block)
            })
            .into_iter()
            .collect();
        let bytes = RedEncoder::encode(primary_pt, &payload, &redundant);
        self.history = Some((payload, rtp_time));
        bytes
    }
}

impl Payloader {
    pub(crate) fn new(spec: CodecSpec, vp9_mode: Vp9PacketizerMode) -> Self {
        let mut pack = CodecPacketizer::new(spec.codec, vp9_mode);

        // Enable DONL for H.265 when sprop-max-don-diff > 0 (RFC 7798 §7.1)
        if let CodecPacketizer::H265(ref mut h265) = pack {
            if spec.format.sprop_max_don_diff.unwrap_or(0) > 0 {
                h265.with_donl(true);
            }
        }

        // Enable DONL for H.266 when sprop-max-don-diff > 0 (RFC 9328 §7.2)
        if let CodecPacketizer::H266(ref mut h266) = pack {
            if spec.format.sprop_max_don_diff.unwrap_or(0) > 0 {
                h266.with_donl(true);
            }
        }

        Payloader {
            pack,
            clock_rate: spec.clock_rate,
            red: None,
        }
    }

    /// Synchronise RED wrapping with the (possibly renegotiated) RED PT: enable it, update its
    /// PT, or disable it, without discarding the codec packetizer or redundancy history. Called
    /// on every payload so a remapped or dropped RED PT can't go stale in a cached payloader.
    pub(crate) fn set_red(&mut self, red_pt: Option<Pt>, primary_pt: Pt) {
        match (red_pt, &mut self.red) {
            (Some(pt), Some(state)) => {
                state.red_pt = pt;
                state.primary_pt = primary_pt;
            }
            (Some(pt), None) => {
                self.red = Some(RedState {
                    red_pt: pt,
                    primary_pt,
                    history: None,
                })
            }
            (None, _) => self.red = None,
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

        let chunks = self.pack.packetize(mtu, data.as_ref())?;
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
                pkt_ext_vals.abs_capture_time = None;
                pkt_ext_vals.user_values.remove::<VideoLayersAllocation>();
            }

            if !last {
                pkt_ext_vals.video_orientation = None;
                pkt_ext_vals.video_content_type = None;
                pkt_ext_vals.video_timing = None;
            }

            let rtp_time_u32 = rtp_time.rebase(self.clock_rate).numer() as u32;

            // When RED is enabled, wrap the payload and swap to the RED PT. The primary
            // stream's SSRC, sequence number and marker are preserved.
            let (write_pt, write_payload) = match &mut self.red {
                Some(red) => (red.red_pt, red.wrap(data, rtp_time_u32)),
                None => (pt, data),
            };

            stream.write_rtp(
                RtpWrite::new(write_pt, seq_no, rtp_time_u32, wallclock, write_payload)
                    .marker(marker)
                    .ext_vals(pkt_ext_vals)
                    .nackable(nackable),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::packet::RedDecoder;

    #[test]
    fn red_wrap_builds_redundancy_from_history() {
        let mut red = RedState {
            red_pt: Pt::new_with_value(63),
            primary_pt: Pt::new_with_value(111),
            history: None,
        };

        // First packet: primary-only RED (no history yet).
        let first = red.wrap(vec![1, 2, 3], 1000);
        let blocks = RedDecoder::decode(&first).unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].is_primary);
        assert_eq!(blocks[0].payload, &[1, 2, 3]);

        // Second packet: carries the first frame as redundancy.
        let second = red.wrap(vec![4, 5], 1960);
        let blocks = RedDecoder::decode(&second).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(!blocks[0].is_primary);
        assert_eq!(blocks[0].pt, 111);
        assert_eq!(blocks[0].timestamp_offset, 960); // 1960 - 1000
        assert_eq!(blocks[0].payload, &[1, 2, 3]);
        assert!(blocks[1].is_primary);
        assert_eq!(blocks[1].payload, &[4, 5]);
    }
}
