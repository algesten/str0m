//! RFC 4867 RTP payload (de)packetization for AMR-WB.
//!
//! AMR-WB is carried per [RFC 4867](https://datatracker.ietf.org/doc/html/rfc4867).
//! A payload is a 4-bit Codec Mode Request (CMR), a table of contents (one entry
//! per frame) and the speech bits for each frame, in either the octet-aligned
//! (`octet-align=1`) or bandwidth-efficient (the SDP default) layout.
//!
//! str0m's application-facing byte stream uses the 3GPP IF / storage format: each
//! frame is a 1-octet header `(FT << 3) | (Q << 2)` (the
//! [RFC 4867 §5.3](https://datatracker.ietf.org/doc/html/rfc4867#section-5.3)
//! frame header) followed by its speech bytes. The depacketizer turns an RTP
//! payload into one or more concatenated IF frames. The packetizer accepts
//! exactly one IF frame per call and turns it into one RTP payload. This is the
//! layout an AMR-WB decoder/encoder consumes directly.
//!
//! Supported: octet-aligned and bandwidth-efficient single-channel payloads and
//! the per-frame table of contents.
//! Not supported (matching the codec's common use): frame interleaving, payload
//! CRC (`crc=1`), robust sorting, and multiple channels.

use super::{CodecExtra, Depacketizer, PacketError, Packetizer};

/// Speech bits carried by each AMR-WB frame type (the `FT` field, 0..=15), per
/// RFC 4867 Table 1a. `None` marks the reserved types FT 10..=13.
const FRAME_TYPE_BITS: [Option<u16>; 16] = [
    Some(132), // 0: 6.60 kbps
    Some(177), // 1: 8.85 kbps
    Some(253), // 2: 12.65 kbps
    Some(285), // 3: 14.25 kbps
    Some(317), // 4: 15.85 kbps
    Some(365), // 5: 18.25 kbps
    Some(397), // 6: 19.85 kbps
    Some(461), // 7: 23.05 kbps
    Some(477), // 8: 23.85 kbps
    Some(40),  // 9: SID (comfort noise)
    None,      // 10: reserved
    None,      // 11: reserved
    None,      // 12: reserved
    None,      // 13: reserved
    Some(0),   // 14: speech lost
    Some(0),   // 15: no data
];

/// Codec Mode Request value meaning "no mode requested" (RFC 4867).
const CMR_NO_REQUEST: u32 = 15;

/// Packetizes AMR-WB RTP packets (RFC 4867).
///
/// Input is exactly one 3GPP IF frame: a `(FT << 3) | (Q << 2)` header octet
/// followed by the speech bytes for that frame. Concatenated frames are rejected
/// because each call supplies only one RTP timestamp, while every AMR-WB frame
/// represents a distinct 20 ms interval. A standalone NO_DATA frame is also
/// rejected, following RFC 4867's recommendation for non-interleaved payloads.
///
/// ## Unversioned API surface
///
/// This struct is not currently versioned according to semver rules.
/// Breaking changes may be made in minor or patch releases.
#[derive(Debug, Default, Copy, Clone)]
pub struct AmrWbPacketizer {
    /// Whether to emit the octet-aligned (`octet-align=1`) layout.
    octet_align: bool,
}

impl AmrWbPacketizer {
    /// Selects the octet-aligned (`true`) or bandwidth-efficient (`false`) layout.
    pub fn with_octet_align(mut self, octet_align: bool) -> Self {
        self.octet_align = octet_align;
        self
    }
}

impl Packetizer for AmrWbPacketizer {
    fn packetize(&mut self, mtu: usize, payload: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        if payload.is_empty() {
            return Ok(vec![]);
        }

        let header = payload[0];
        if header & 0b1000_0011 != 0 {
            return Err(PacketError::ErrAmrWbCorruptedPacket);
        }

        let frame_type = (header >> 3) & 0x0f;
        let bits = FRAME_TYPE_BITS[frame_type as usize]
            .map(usize::from)
            .ok_or(PacketError::ErrAmrWbCorruptedPacket)?;
        let expected_len = 1 + bits.div_ceil(8);
        if payload.len() < expected_len {
            return Err(PacketError::ErrShortPacket);
        }
        if payload.len() != expected_len || frame_type == 15 {
            return Err(PacketError::ErrAmrWbCorruptedPacket);
        }

        let packet = build_payload(payload, self.octet_align);
        if packet.len() > mtu {
            return Err(PacketError::PacketSizeLargerThanMtu(packet.len(), mtu));
        }

        Ok(vec![packet])
    }

    fn is_marker(&mut self, _data: &[u8], _previous: Option<&[u8]>, _last: bool) -> bool {
        false
    }
}

/// Depacketizes AMR-WB RTP packets (RFC 4867).
///
/// Each RTP payload is turned into concatenated 3GPP IF frames written to `out`:
/// per frame a `(FT << 3) | (Q << 2)` header octet followed by the speech bytes.
///
/// ## Unversioned API surface
///
/// This struct is not currently versioned according to semver rules.
/// Breaking changes may be made in minor or patch releases.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct AmrWbDepacketizer {
    /// Whether the payload uses the octet-aligned (`octet-align=1`) layout.
    octet_align: bool,
}

impl AmrWbDepacketizer {
    /// Selects the octet-aligned (`true`) or bandwidth-efficient (`false`) layout.
    pub fn with_octet_align(mut self, octet_align: bool) -> Self {
        self.octet_align = octet_align;
        self
    }
}

impl Depacketizer for AmrWbDepacketizer {
    fn out_size_hint(&self, packets_size: usize) -> Option<usize> {
        // Even a payload consisting entirely of zero-length frame types has a
        // six-bit ToC entry for every one-byte IF header, so twice the packet size
        // is a conservative allocation hint.
        Some(packets_size.saturating_mul(2))
    }

    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
        _: &mut CodecExtra,
    ) -> Result<(), PacketError> {
        if packet.is_empty() {
            return Ok(());
        }

        let mut reader = BitReader::new(packet);

        // Payload header: CMR, plus 4 reserved bits when octet-aligned.
        let _cmr = reader.get_bits(4)?;
        if self.octet_align {
            reader.get_bits(4)?;
        }

        // Table of contents: F (more frames follow), FT, Q for each frame. The
        // packet length itself bounds the number of entries.
        let mut toc = Vec::new();
        loop {
            let follows = reader.get_bits(1)? != 0;
            let frame_type = reader.get_bits(4)? as u8;
            let good = reader.get_bits(1)? != 0;
            if self.octet_align {
                reader.get_bits(2)?;
            }
            toc.push((frame_type, good));
            if !follows {
                break;
            }
        }

        // Speech data: one block per ToC entry, written as an IF frame.
        for (frame_type, good) in toc {
            let bits = FRAME_TYPE_BITS[(frame_type & 0x0f) as usize]
                .ok_or(PacketError::ErrAmrWbCorruptedPacket)?;

            out.push((frame_type << 3) | (u8::from(good) << 2));
            reader.get_frame_into(usize::from(bits), out)?;

            if self.octet_align {
                reader.align_to_byte();
            }
        }

        // RFC 4867 section 4.5.1 recommends discarding a packet when its actual
        // length differs from the length implied by the ToC. Bandwidth-efficient
        // payloads may end in at most seven zero padding bits.
        let remaining = reader.remaining();
        if remaining >= 8 || (remaining > 0 && reader.get_bits(remaining)? != 0) {
            return Err(PacketError::ErrAmrWbCorruptedPacket);
        }

        Ok(())
    }

    fn is_partition_head(&self, _packet: &[u8]) -> bool {
        true
    }

    fn is_partition_tail(&self, _marker: bool, _packet: &[u8]) -> bool {
        true
    }
}

/// Builds one RFC 4867 RTP payload (CMR = "no request") from one validated
/// 3GPP IF frame, allocating only the returned buffer.
///
/// The caller guarantees `if_frame` is well-formed.
fn build_payload(if_frame: &[u8], octet_align: bool) -> Vec<u8> {
    // Octet-aligned output is one payload header plus the complete IF frame.
    // the bandwidth-efficient layout is never larger, so this never reallocates.
    let mut writer = BitWriter::with_capacity(1 + if_frame.len());

    // Payload header: CMR (4 bits) + 4 reserved zero bits when octet-aligned.
    writer.put_bits(CMR_NO_REQUEST, 4);
    if octet_align {
        writer.put_bits(0, 4);
    }

    let header = if_frame[0];
    let frame_type = (header >> 3) & 0x0f;
    let good = (header >> 2) & 0x01 != 0;
    let bits = FRAME_TYPE_BITS[frame_type as usize].map_or(0, usize::from);

    writer.put_bits(0, 1); // F: this is the only frame.
    writer.put_bits(u32::from(frame_type), 4);
    writer.put_bits(u32::from(good), 1);
    if octet_align {
        writer.put_bits(0, 2);
    }

    writer.put_frame(&if_frame[1..], bits);
    if octet_align {
        writer.align_to_byte();
    }

    writer.into_bytes()
}

/// Most-significant-bit-first writer over a growing byte buffer.
#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    nbits: u32,
}

impl BitWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            out: Vec::with_capacity(capacity),
            acc: 0,
            nbits: 0,
        }
    }

    /// Appends the low `count` bits of `value` (`count` <= 8), MSB first.
    fn put_bits(&mut self, value: u32, count: u32) {
        let mask = (1u64 << count) - 1;
        self.acc = (self.acc << count) | (u64::from(value) & mask);
        self.nbits += count;
        while self.nbits >= 8 {
            self.nbits -= 8;
            self.out.push((self.acc >> self.nbits) as u8);
        }
        self.acc &= (1u64 << self.nbits) - 1;
    }

    /// Appends `bits` speech bits read MSB-first from `data` (zero-padded short).
    fn put_frame(&mut self, data: &[u8], bits: usize) {
        let whole_bytes = bits / 8;
        for offset in 0..whole_bytes {
            self.put_bits(u32::from(data.get(offset).copied().unwrap_or(0)), 8);
        }
        let remainder = (bits % 8) as u32;
        if remainder > 0 {
            let byte = data.get(whole_bytes).copied().unwrap_or(0);
            self.put_bits(u32::from(byte >> (8 - remainder)), remainder);
        }
    }

    /// Pads the current byte with zero bits up to the next octet boundary.
    fn align_to_byte(&mut self) {
        if self.nbits != 0 {
            self.put_bits(0, 8 - self.nbits);
        }
    }

    /// Finishes writing, zero-padding any partial trailing byte.
    fn into_bytes(mut self) -> Vec<u8> {
        self.align_to_byte();
        self.out
    }
}

/// Most-significant-bit-first reader over a byte slice.
struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() * 8 - self.bit_pos
    }

    /// Reads `count` bits (`count` <= 32), MSB first.
    fn get_bits(&mut self, count: usize) -> Result<u32, PacketError> {
        if self.remaining() < count {
            return Err(PacketError::ErrShortPacket);
        }
        let mut value = 0u32;
        for _ in 0..count {
            let bit = (self.data[self.bit_pos / 8] >> (7 - (self.bit_pos % 8))) & 1;
            value = (value << 1) | u32::from(bit);
            self.bit_pos += 1;
        }
        Ok(value)
    }

    /// Reads `bits` speech bits MSB-first, appending `ceil(bits / 8)` octet-aligned
    /// (zero-padded) bytes to `out`.
    fn get_frame_into(&mut self, bits: usize, out: &mut Vec<u8>) -> Result<(), PacketError> {
        if self.remaining() < bits {
            return Err(PacketError::ErrShortPacket);
        }
        let start = out.len();
        out.resize(start + bits.div_ceil(8), 0);
        for index in 0..bits {
            let bit = (self.data[self.bit_pos / 8] >> (7 - (self.bit_pos % 8))) & 1;
            out[start + index / 8] |= bit << (7 - (index % 8));
            self.bit_pos += 1;
        }
        Ok(())
    }

    /// Skips forward to the next octet boundary.
    fn align_to_byte(&mut self) {
        let into_byte = self.bit_pos % 8;
        if into_byte != 0 {
            self.bit_pos += 8 - into_byte;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Builds an IF frame: header octet `(FT << 3) | (Q << 2)` then `fill` bytes,
    /// with padding bits in the final byte zeroed so it round-trips byte-for-byte.
    fn if_frame(frame_type: u8, good: bool, fill: u8) -> Vec<u8> {
        let bits = FRAME_TYPE_BITS[frame_type as usize].unwrap() as usize;
        let mut data = vec![fill; bits.div_ceil(8)];
        let remainder = bits % 8;
        if remainder != 0 {
            if let Some(last) = data.last_mut() {
                *last &= 0xffu8 << (8 - remainder);
            }
        }
        let mut out = vec![(frame_type << 3) | (u8::from(good) << 2)];
        out.extend_from_slice(&data);
        out
    }

    fn round_trip(octet_align: bool, frames: &[Vec<u8>]) {
        let input: Vec<u8> = frames.concat();
        let mut pack = AmrWbPacketizer::default().with_octet_align(octet_align);
        let mut depack = AmrWbDepacketizer::default().with_octet_align(octet_align);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        for frame in frames {
            let packets = pack.packetize(1500, frame).unwrap();
            assert_eq!(packets.len(), 1, "expected one packet per IF frame");
            depack
                .depacketize(&packets[0], &mut out, &mut extra)
                .unwrap();
        }
        assert_eq!(out, input, "IF frames must survive the round-trip");
    }

    #[test]
    fn octet_aligned_round_trip() {
        round_trip(true, &[if_frame(8, true, 0xa5), if_frame(2, true, 0x5a)]);
    }

    #[test]
    fn bandwidth_efficient_round_trip() {
        round_trip(false, &[if_frame(0, true, 0xff), if_frame(8, true, 0x33)]);
    }

    #[test]
    fn octet_aligned_single_frame_layout_matches_rfc() {
        // CMR 15 + single FT 8 frame: header 0xF0, ToC 0x44 (F=0 FT=1000 Q=1),
        // then 60 octet-aligned speech bytes (477 bits rounded up).
        let input = if_frame(8, true, 0x00);
        let mut pack = AmrWbPacketizer::default().with_octet_align(true);
        let packets = pack.packetize(1500, &input).unwrap();
        assert_eq!(packets[0].len(), 1 + 1 + 60);
        assert_eq!(packets[0][0], 0xf0);
        assert_eq!(packets[0][1], 0x44);
    }

    #[test]
    fn standalone_no_data_is_rejected() {
        let input = if_frame(15, false, 0);
        let mut pack = AmrWbPacketizer::default().with_octet_align(true);
        assert_eq!(
            pack.packetize(1500, &input),
            Err(PacketError::ErrAmrWbCorruptedPacket)
        );
    }

    #[test]
    fn no_data_is_accepted_from_peer() {
        // CMR=15 followed by FT=15, Q=1 and no speech data.
        let payload = [0xf0, 0x7c];
        let mut depack = AmrWbDepacketizer::default().with_octet_align(true);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;

        depack.depacketize(&payload, &mut out, &mut extra).unwrap();

        assert_eq!(out, vec![0x7c]);
    }

    #[test]
    fn empty_payload_depacketizes_to_nothing() {
        let mut depack = AmrWbDepacketizer::default().with_octet_align(true);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        depack.depacketize(&[], &mut out, &mut extra).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn empty_input_produces_no_packets() {
        let mut pack = AmrWbPacketizer::default().with_octet_align(true);
        assert!(pack.packetize(1500, &[]).unwrap().is_empty());
        assert_eq!(
            pack.packetize(0, &if_frame(8, true, 1)),
            Err(PacketError::PacketSizeLargerThanMtu(62, 0))
        );
    }

    #[test]
    fn truncated_speech_data_is_rejected() {
        // FT 8 needs 60 speech bytes; supply only the header and ToC.
        let payload = [0xf0, 0x44];
        let mut depack = AmrWbDepacketizer::default().with_octet_align(true);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        assert_eq!(
            depack.depacketize(&payload, &mut out, &mut extra),
            Err(PacketError::ErrShortPacket)
        );
    }

    #[test]
    fn reserved_frame_type_is_rejected() {
        // CMR 0, ToC F=0 FT=1011 (11, reserved) Q=0 + pad = 0x58.
        let payload = [0x00, 0x58];
        let mut depack = AmrWbDepacketizer::default().with_octet_align(true);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        assert_eq!(
            depack.depacketize(&payload, &mut out, &mut extra),
            Err(PacketError::ErrAmrWbCorruptedPacket)
        );
    }

    #[test]
    fn packetizer_rejects_frame_larger_than_mtu() {
        let input = if_frame(8, true, 0x11);
        let mut pack = AmrWbPacketizer::default().with_octet_align(true);
        assert_eq!(
            pack.packetize(61, &input),
            Err(PacketError::PacketSizeLargerThanMtu(62, 61))
        );
    }

    #[test]
    fn packetizer_rejects_concatenated_if_frames() {
        let input: Vec<u8> = [
            if_frame(2, true, 0x12),
            if_frame(9, true, 0x34), // SID
        ]
        .concat();
        let mut pack = AmrWbPacketizer::default().with_octet_align(true);
        assert_eq!(
            pack.packetize(1500, &input),
            Err(PacketError::ErrAmrWbCorruptedPacket)
        );
    }

    #[test]
    fn packetizer_rejects_reserved_frame_type() {
        // IF header with FT=10 (reserved): (10 << 3) = 0x50.
        let input = [0x50];
        let mut pack = AmrWbPacketizer::default().with_octet_align(true);
        assert_eq!(
            pack.packetize(1500, &input),
            Err(PacketError::ErrAmrWbCorruptedPacket)
        );
    }

    #[test]
    fn packetizer_rejects_truncated_if_frame() {
        // IF header for FT=8 (needs 60 speech bytes) with no speech bytes following.
        let input = [(8 << 3) | (1 << 2)];
        let mut pack = AmrWbPacketizer::default().with_octet_align(true);
        assert_eq!(
            pack.packetize(1500, &input),
            Err(PacketError::ErrShortPacket)
        );
    }

    #[test]
    fn depacketizer_accepts_more_than_twelve_frames() {
        // RFC 4867 has no fixed 240 ms maximum. Use thirteen zero-length
        // SPEECH_LOST entries to exercise a compound payload beyond 12 frames.
        let mut payload = vec![0xf0];
        payload.extend(std::iter::repeat_n(0xf0, 12));
        payload.push(0x70);
        let mut depack = AmrWbDepacketizer::default().with_octet_align(true);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        depack.depacketize(&payload, &mut out, &mut extra).unwrap();
        assert_eq!(out, vec![0x70; 13]);
    }

    #[test]
    fn depacketizer_rejects_trailing_octet() {
        for octet_align in [false, true] {
            let frame = if_frame(0, true, 0x55);
            let mut payload = build_payload(&frame, octet_align);
            payload.push(0);

            let mut depack = AmrWbDepacketizer::default().with_octet_align(octet_align);
            let mut out = Vec::new();
            let mut extra = CodecExtra::None;
            assert_eq!(
                depack.depacketize(&payload, &mut out, &mut extra),
                Err(PacketError::ErrAmrWbCorruptedPacket)
            );
        }
    }

    #[test]
    fn depacketizer_rejects_nonzero_terminal_padding() {
        let frame = if_frame(0, true, 0x55);
        let mut payload = build_payload(&frame, false);
        *payload.last_mut().unwrap() |= 1;

        let mut depack = AmrWbDepacketizer::default().with_octet_align(false);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        assert_eq!(
            depack.depacketize(&payload, &mut out, &mut extra),
            Err(PacketError::ErrAmrWbCorruptedPacket)
        );
    }
}
