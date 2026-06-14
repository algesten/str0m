use std::collections::VecDeque;

use crate::format::Vp9PacketizerMode;
use crate::format::{Codec, CodecSpec};
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
    allow_talkspurt_marker: bool,
    red: Option<RedState>,
}

/// Send-side RFC 2198 RED state. `distances` lists how many packets back each redundant level
/// carries (`[1]` = one level, the previous packet; `[1, 3, 5]` = three levels for higher loss),
/// always sorted, distinct and >= 1. `history` keeps the most recent `max(distances)` payloads.
#[derive(Debug)]
struct RedState {
    red_pt: Pt,
    primary_pt: Pt,
    distances: Box<[u32]>,
    /// The most recent payloads as `(payload, rtp_time)`, oldest at the front, capped at the
    /// deepest configured distance so it never grows without bound.
    history: VecDeque<(Vec<u8>, u32)>,
}

impl RedState {
    /// Wrap the primary `payload` (at `rtp_time`) into a RED payload, prepending one redundant
    /// block per configured distance that has a matching history entry and fits RFC 2198's field
    /// limits (a block over the 10-bit, 1023-byte length field does not fit and is dropped, so RED
    /// adds no protection for audio frames that large). The most recent (shallowest, most valuable)
    /// levels are added first and the deepest are dropped once the encoded packet would exceed
    /// `budget` bytes. That size guard keeps the RED packet within the send MTU, which both avoids
    /// IP fragmentation (a fragmented RED packet loses all its redundancy if any fragment drops) and
    /// prevents overflowing the fixed datagram buffer downstream. Kept blocks are emitted
    /// oldest-first as RFC 2198 requires, then the primary. Updates history.
    fn wrap(&mut self, payload: Vec<u8>, rtp_time: u32, budget: usize) -> Vec<u8> {
        let primary_pt = *self.primary_pt;
        let len = self.history.len();

        // Room for redundancy after the primary payload and its 1-byte RED header. `saturating_sub`
        // gives 0 for a near-MTU primary, so we send it primary-only rather than overflow. RFC 2198
        // headers: 1 byte for the primary block, 4 bytes for each redundant block.
        let mut remaining = budget.saturating_sub(payload.len() + 1);

        // Add the most recent levels first (distance 1 is the most valuable). Collected here
        // shallowest-first, then reversed to oldest-first for the wire.
        let mut kept: Vec<RedundantBlock> = Vec::new();
        for &d in self.distances.iter() {
            let Some((prev, prev_time)) = len
                .checked_sub(d as usize)
                .and_then(|i| self.history.get(i))
            else {
                continue;
            };
            let block = RedundantBlock {
                pt: primary_pt,
                timestamp_offset: rtp_time.wrapping_sub(*prev_time),
                payload: prev.clone(),
            };
            // A distance whose offset or length overflows RFC 2198's fields is skipped, not sent
            // malformed; the primary still goes out, so this only drops redundancy.
            if !block.fits() {
                continue;
            }
            let cost = 4 + block.payload.len();
            if cost > remaining {
                // Out of budget: stop so the kept (shallowest) levels stay contiguous. Redundancy
                // never pushes the encoded RED past `budget`; only the 1-byte primary header can,
                // and only for a primary that already fills the MTU — still far under the buffer.
                break;
            }
            remaining -= cost;
            kept.push(block);
        }
        // RFC 2198 requires redundant blocks oldest-first (largest distance first), then primary.
        kept.reverse();

        let bytes = RedEncoder::encode(primary_pt, &payload, &kept);
        self.history.push_back((payload, rtp_time));
        let max_distance = self.distances.last().copied().unwrap_or(1) as usize;
        while self.history.len() > max_distance {
            self.history.pop_front();
        }
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
            clock_rate: spec.rtp_clock_rate(),
            allow_talkspurt_marker: spec.codec != Codec::CN,
            red: None,
        }
    }

    /// Synchronise RED wrapping with the current RED PT and distance pattern: enable it, update
    /// its PT/distances, or disable it, without discarding the codec packetizer. Called on every
    /// payload so a remapped or dropped RED PT, a changed distance pattern, or a runtime on/off
    /// toggle can't go stale in a cached payloader. `distances` must be sorted, distinct and >= 1.
    pub(crate) fn set_red(&mut self, red_pt: Option<Pt>, primary_pt: Pt, distances: &[u32]) {
        match (red_pt, &mut self.red) {
            (Some(pt), Some(state)) => {
                state.red_pt = pt;
                state.primary_pt = primary_pt;
                // Keep the redundancy history (a live talk-spurt) across a PT remap, but if the
                // distance pattern changed, adopt it and trim history to the new deepest distance.
                if *state.distances != *distances {
                    state.distances = distances.into();
                    let max_distance = distances.last().copied().unwrap_or(1) as usize;
                    while state.history.len() > max_distance {
                        state.history.pop_front();
                    }
                }
            }
            (Some(pt), None) => {
                self.red = Some(RedState {
                    red_pt: pt,
                    primary_pt,
                    distances: distances.into(),
                    history: VecDeque::new(),
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
                || (is_audio && self.allow_talkspurt_marker && start_of_talk_spurt);

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
            // stream's SSRC, sequence number and marker are preserved. `mtu` is the same
            // aligned budget the chunk was packetized to, so RED redundancy is shed rather than
            // pushing the packet over the MTU.
            let (write_pt, write_payload) = match &mut self.red {
                Some(red) => (red.red_pt, red.wrap(data, rtp_time_u32, mtu)),
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

    // A budget large enough not to interfere with the small-payload tests below.
    const BUDGET: usize = 1200;

    fn red_state(distances: &[u32]) -> RedState {
        RedState {
            red_pt: Pt::new_with_value(63),
            primary_pt: Pt::new_with_value(111),
            distances: distances.into(),
            history: VecDeque::new(),
        }
    }

    #[test]
    fn red_wrap_builds_redundancy_from_history() {
        let mut red = red_state(&[1]);

        // First packet: primary-only RED (no history yet).
        let first = red.wrap(vec![1, 2, 3], 1000, BUDGET);
        let blocks = RedDecoder::decode(&first).unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].is_primary);
        assert_eq!(blocks[0].payload, &[1, 2, 3]);

        // Second packet: carries the first frame as redundancy.
        let second = red.wrap(vec![4, 5], 1960, BUDGET);
        let blocks = RedDecoder::decode(&second).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(!blocks[0].is_primary);
        assert_eq!(blocks[0].pt, 111);
        assert_eq!(blocks[0].timestamp_offset, 960); // 1960 - 1000
        assert_eq!(blocks[0].payload, &[1, 2, 3]);
        assert!(blocks[1].is_primary);
        assert_eq!(blocks[1].payload, &[4, 5]);
    }

    #[test]
    fn red_wrap_multi_distance_emits_levels_oldest_first() {
        // A [1, 3] pattern: once enough history exists, each packet carries the previous frame
        // (distance 1) and the frame three back (distance 3), emitted oldest-first before primary.
        let mut red = red_state(&[1, 3]);

        // Feed frames 0..=3 at 960-tick spacing. Only from the 4th packet is distance 3 available.
        for i in 0..4u32 {
            red.wrap(vec![i as u8], i * 960, BUDGET);
        }
        let fifth = red.wrap(vec![42], 4 * 960, BUDGET);
        let blocks = RedDecoder::decode(&fifth).unwrap();

        // Oldest-first: distance 3 (frame at 960), distance 1 (frame at 3*960), then primary.
        assert_eq!(blocks.len(), 3);
        assert!(!blocks[0].is_primary);
        assert_eq!(blocks[0].timestamp_offset, 3 * 960); // 4*960 - 1*960
        assert_eq!(blocks[0].payload, &[1]);
        assert!(!blocks[1].is_primary);
        assert_eq!(blocks[1].timestamp_offset, 960); // 4*960 - 3*960
        assert_eq!(blocks[1].payload, &[3]);
        assert!(blocks[2].is_primary);
        assert_eq!(blocks[2].payload, &[42]);
    }

    #[test]
    fn red_wrap_skips_redundancy_that_overflows_rfc_fields() {
        // A distance whose timestamp offset exceeds RFC 2198's 14-bit field is dropped, not sent
        // malformed; the primary and any in-range level still go out.
        let mut red = red_state(&[1]);
        red.wrap(vec![1], 0, BUDGET);
        // Next frame is 0x4000 ticks later: offset 16384 overflows the 14-bit field, so no
        // redundant block, just the primary.
        let out = red.wrap(vec![2], 0x4000, BUDGET);
        let blocks = RedDecoder::decode(&out).unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].is_primary);
    }

    #[test]
    fn red_wrap_sheds_deepest_redundancy_to_fit_budget() {
        // Large frames whose redundancy cannot all fit the budget. Without this guard the encoded
        // RED payload (primary + every redundant copy) overflows the fixed downstream datagram
        // buffer and panics; with it, the deepest (oldest) levels are shed and the packet fits.
        let mut red = red_state(&[1, 2]);
        let budget = 300;
        let frame = |b: u8| vec![b; 100];

        red.wrap(frame(0xAA), 0, budget); // distance-2 source
        red.wrap(frame(0xBB), 960, budget); // distance-1 source
        let out = red.wrap(frame(0xCC), 1920, budget);

        // Never exceeds the budget, which is the property that prevents the downstream overflow.
        assert!(
            out.len() <= budget,
            "encoded RED {} > budget {budget}",
            out.len()
        );

        let blocks = RedDecoder::decode(&out).unwrap();
        // primary (0xCC) = 101 bytes; distance 1 (0xBB) = 104; together 205 <= 300, but adding
        // distance 2 (0xAA, another 104) would be 309 > 300, so the deepest level is shed.
        assert_eq!(blocks.len(), 2, "distance 2 shed to fit budget");
        assert!(!blocks[0].is_primary);
        assert_eq!(
            blocks[0].payload,
            &frame(0xBB)[..],
            "kept the shallowest (distance 1)"
        );
        assert!(blocks[1].is_primary);
        assert_eq!(blocks[1].payload, &frame(0xCC)[..]);

        // With ample budget the same state keeps both levels, confirming the guard is what sheds.
        let mut red = red_state(&[1, 2]);
        red.wrap(frame(0xAA), 0, BUDGET);
        red.wrap(frame(0xBB), 960, BUDGET);
        let out = red.wrap(frame(0xCC), 1920, BUDGET);
        assert_eq!(
            RedDecoder::decode(&out).unwrap().len(),
            3,
            "all levels fit a large budget"
        );
    }
}
