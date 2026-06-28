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
//! payload into one or more concatenated IF frames; the packetizer turns
//! concatenated IF frames back into an RTP payload. This is the layout an AMR-WB
//! decoder/encoder consumes directly.
//!
//! Supported: octet-aligned and bandwidth-efficient single-channel payloads, the
//! per-frame table of contents, and up to [`MAX_FRAMES_PER_PACKET`] frames.
//! Not supported (matching the codec's common use): frame interleaving, payload
//! CRC (`crc=1`), robust sorting, and multiple channels.

use super::{CodecExtra, Depacketizer, PacketError, Packetizer};

/// Largest number of frames one packet may carry (RFC 4867 MAX-PTIME of 240 ms
/// at 20 ms per AMR-WB frame).
pub const MAX_FRAMES_PER_PACKET: usize = 12;

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
/// Input bytes are concatenated 3GPP IF frames (a `(FT << 3) | (Q << 2)` header
/// octet followed by the speech bytes for that frame). Output is one RTP payload
/// per [`Packetizer::packetize`] call, split across packets only on whole-frame
/// boundaries when it would otherwise exceed the MTU.
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
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        let octet_align = self.octet_align;
        let mut packets = Vec::new();

        // Walk the concatenated IF frames by byte offset, grouping whole frames
        // into packets that fit the MTU. Nothing is allocated per frame: each
        // packet is built directly from the input sub-slice [group_start, offset).
        let mut group_start = 0;
        let mut count = 0;
        let mut speech_bytes = 0;
        let mut speech_bits = 0;

        let mut offset = 0;
        while offset < payload.len() {
            let frame_type = (payload[offset] >> 3) & 0x0f;
            let bits = match FRAME_TYPE_BITS[frame_type as usize] {
                Some(bits) => usize::from(bits),
                None => return Err(PacketError::ErrAmrWbCorruptedPacket),
            };
            let nbytes = bits.div_ceil(8);
            let frame_end = offset + 1 + nbytes;
            if frame_end > payload.len() {
                return Err(PacketError::ErrShortPacket);
            }

            let would_overflow = count > 0
                && (count >= MAX_FRAMES_PER_PACKET
                    || encoded_len(
                        octet_align,
                        count + 1,
                        speech_bytes + nbytes,
                        speech_bits + bits,
                    ) > mtu);

            if would_overflow {
                packets.push(build_payload(&payload[group_start..offset], octet_align));
                group_start = offset;
                count = 0;
                speech_bytes = 0;
                speech_bits = 0;
            }

            count += 1;
            speech_bytes += nbytes;
            speech_bits += bits;
            offset = frame_end;
        }

        if count > 0 {
            packets.push(build_payload(&payload[group_start..], octet_align));
        }

        Ok(packets)
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
        // IF output adds at most one header octet per frame and never includes the
        // CMR/ToC bytes, so the payload size plus a per-frame header allowance is a
        // safe upper bound for the common case.
        Some(packets_size + MAX_FRAMES_PER_PACKET)
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

        // Table of contents: F (more frames follow), FT, Q for each frame. Bounded
        // by MAX_FRAMES_PER_PACKET, so it lives on the stack with no allocation.
        let mut toc = [(0u8, false); MAX_FRAMES_PER_PACKET];
        let mut toc_len = 0;
        loop {
            let follows = reader.get_bits(1)? != 0;
            let frame_type = reader.get_bits(4)? as u8;
            let good = reader.get_bits(1)? != 0;
            if self.octet_align {
                reader.get_bits(2)?;
            }
            if toc_len == MAX_FRAMES_PER_PACKET {
                return Err(PacketError::ErrAmrWbCorruptedPacket);
            }
            toc[toc_len] = (frame_type, good);
            toc_len += 1;
            if !follows {
                break;
            }
        }

        // Speech data: one block per ToC entry, written as an IF frame.
        for &(frame_type, good) in &toc[..toc_len] {
            let bits = FRAME_TYPE_BITS[(frame_type & 0x0f) as usize]
                .ok_or(PacketError::ErrAmrWbCorruptedPacket)?;

            out.push((frame_type << 3) | (u8::from(good) << 2));
            reader.get_frame_into(usize::from(bits), out)?;

            if self.octet_align {
                reader.align_to_byte();
            }
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

/// Exact RTP payload length in bytes for `count` frames carrying `speech_bytes`
/// octet-aligned speech bytes (or `speech_bits` raw speech bits), in the chosen
/// layout.
fn encoded_len(octet_align: bool, count: usize, speech_bytes: usize, speech_bits: usize) -> usize {
    if octet_align {
        // 1 header octet + 1 ToC octet per frame + byte-aligned speech.
        1 + count + speech_bytes
    } else {
        // 4 CMR bits + 6 ToC bits per frame + speech bits, rounded up.
        (4 + 6 * count + speech_bits).div_ceil(8)
    }
}

/// Builds one RFC 4867 RTP payload (CMR = "no request") from a slice of
/// concatenated 3GPP IF frames, allocating only the returned buffer.
///
/// The caller guarantees `if_bytes` is well-formed: it is the exact range of
/// frames already validated by [`AmrWbPacketizer::packetize`].
fn build_payload(if_bytes: &[u8], octet_align: bool) -> Vec<u8> {
    // Octet-aligned output is 1 + nframes + speech_bytes = 1 + if_bytes.len();
    // the bandwidth-efficient layout is never larger, so this never reallocates.
    let mut writer = BitWriter::with_capacity(1 + if_bytes.len());

    // Payload header: CMR (4 bits) + 4 reserved zero bits when octet-aligned.
    writer.put_bits(CMR_NO_REQUEST, 4);
    if octet_align {
        writer.put_bits(0, 4);
    }

    // Pass 1 — table of contents (F, FT, Q per frame, in order).
    let mut offset = 0;
    while offset < if_bytes.len() {
        let header = if_bytes[offset];
        let frame_type = (header >> 3) & 0x0f;
        let good = (header >> 2) & 0x01 != 0;
        let bits = FRAME_TYPE_BITS[frame_type as usize].map_or(0, usize::from);
        let next = offset + 1 + bits.div_ceil(8);
        writer.put_bits(u32::from(next < if_bytes.len()), 1); // F: more frames follow
        writer.put_bits(u32::from(frame_type), 4);
        writer.put_bits(u32::from(good), 1);
        if octet_align {
            writer.put_bits(0, 2);
        }
        offset = next;
    }

    // Pass 2 — speech data (byte-aligned when octet-aligned).
    let mut offset = 0;
    while offset < if_bytes.len() {
        let frame_type = (if_bytes[offset] >> 3) & 0x0f;
        let bits = FRAME_TYPE_BITS[frame_type as usize].map_or(0, usize::from);
        let nbytes = bits.div_ceil(8);
        writer.put_frame(&if_bytes[offset + 1..offset + 1 + nbytes], bits);
        if octet_align {
            writer.align_to_byte();
        }
        offset += 1 + nbytes;
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
        let packets = pack.packetize(1500, &input).unwrap();
        assert_eq!(packets.len(), 1, "expected a single packet");

        let mut depack = AmrWbDepacketizer::default().with_octet_align(octet_align);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        depack
            .depacketize(&packets[0], &mut out, &mut extra)
            .unwrap();
        assert_eq!(out, input, "IF frames must survive the round-trip");
    }

    #[test]
    fn octet_aligned_round_trip() {
        round_trip(
            true,
            &[
                if_frame(8, true, 0xa5),
                if_frame(2, true, 0x5a),
                if_frame(15, false, 0), // no-data
            ],
        );
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
    fn no_data_octet_aligned_is_two_bytes() {
        let input = if_frame(15, false, 0);
        let mut pack = AmrWbPacketizer::default().with_octet_align(true);
        let packets = pack.packetize(1500, &input).unwrap();
        // Header 0xF0, ToC F=0 FT=1111 Q=0 + 2 pad = 0x78.
        assert_eq!(packets[0], vec![0xf0, 0x78]);
    }

    #[test]
    fn no_data_bandwidth_efficient_layout() {
        let input = if_frame(15, false, 0);
        let mut pack = AmrWbPacketizer::default().with_octet_align(false);
        let packets = pack.packetize(1500, &input).unwrap();
        // CMR 1111 then ToC F=0 FT=1111 Q=0 = 1111 011110, zero-padded to 16 bits.
        assert_eq!(packets[0], vec![0xf7, 0x80]);
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
        assert!(pack.packetize(0, &if_frame(8, true, 1)).unwrap().is_empty());
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
    fn packetizer_splits_on_mtu_boundary() {
        // Three FT 8 frames (~61 bytes each as IF) won't fit one small MTU.
        let input: Vec<u8> = [
            if_frame(8, true, 0x11),
            if_frame(8, true, 0x22),
            if_frame(8, true, 0x33),
        ]
        .concat();
        let mut pack = AmrWbPacketizer::default().with_octet_align(true);
        // MTU only fits a single 62-byte (1 + 1 + 60) packet at a time.
        let packets = pack.packetize(80, &input).unwrap();
        assert_eq!(packets.len(), 3);
        for p in &packets {
            assert!(p.len() <= 80, "packet exceeds mtu: {}", p.len());
        }

        // Depacketizing all three reconstructs the original IF stream.
        let mut depack = AmrWbDepacketizer::default().with_octet_align(true);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        for p in &packets {
            depack.depacketize(p, &mut out, &mut extra).unwrap();
        }
        assert_eq!(out, input);
    }

    #[test]
    fn multiple_frames_one_packet() {
        let input: Vec<u8> = [
            if_frame(2, true, 0x12),
            if_frame(9, true, 0x34), // SID
            if_frame(2, false, 0x56),
        ]
        .concat();
        let mut pack = AmrWbPacketizer::default().with_octet_align(true);
        let packets = pack.packetize(1500, &input).unwrap();
        assert_eq!(packets.len(), 1);

        let mut depack = AmrWbDepacketizer::default().with_octet_align(true);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        depack
            .depacketize(&packets[0], &mut out, &mut extra)
            .unwrap();
        assert_eq!(out, input);
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
    fn depacketizer_rejects_more_than_max_frames() {
        // CMR 0xF0 then MAX_FRAMES_PER_PACKET + 1 no-data ToC entries
        // (F=1, FT=1111, Q=0 = 0xF8). The extra entry overflows the stack ToC.
        let mut payload = vec![0xf8u8; MAX_FRAMES_PER_PACKET + 2];
        payload[0] = 0xf0; // CMR header + reserved nibble
        let mut depack = AmrWbDepacketizer::default().with_octet_align(true);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        assert_eq!(
            depack.depacketize(&payload, &mut out, &mut extra),
            Err(PacketError::ErrAmrWbCorruptedPacket)
        );
    }
}
