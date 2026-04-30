/// Fixed-length bit-packed delta encoding compatible with WebRTC's `delta_encoding.cc`.
///
/// This module implements the exact same binary format as Chrome/libWebRTC's
/// RTC event log v2 delta encoding, ensuring output files are parseable by
/// existing WebRTC tools (`webrtc_event_log_visualizer`, `event_log_analyzer`, etc.).

// -- BitWriter ----------------------------------------------------------------

/// Sub-byte-aligned bit writer. Packs bits MSB-first into a byte buffer,
/// matching WebRTC's `BitBufferWriter` which writes MSB-first.
pub(crate) struct BitWriter {
    buf: Vec<u8>,
    /// Bit position within the current byte (0 = MSB, 7 = LSB).
    bit_offset: usize,
}

impl BitWriter {
    pub fn with_capacity(byte_count: usize) -> Self {
        BitWriter {
            buf: vec![0u8; byte_count],
            bit_offset: 0,
        }
    }

    /// Write `bit_count` bits from `val` (MSB-first).
    pub fn write_bits(&mut self, val: u64, bit_count: usize) {
        debug_assert!(bit_count <= 64);
        for i in (0..bit_count).rev() {
            let bit = ((val >> i) & 1) as u8;
            let byte_pos = self.bit_offset / 8;
            let bit_pos = 7 - (self.bit_offset % 8); // MSB first
            if byte_pos >= self.buf.len() {
                self.buf.push(0);
            }
            self.buf[byte_pos] |= bit << bit_pos;
            self.bit_offset += 1;
        }
    }

    /// Write raw bytes (8 bits per byte).
    pub fn write_bytes(&mut self, data: &[u8]) {
        for &b in data {
            self.write_bits(b as u64, 8);
        }
    }

    /// Consume the writer and return the packed bytes, truncated to the
    /// minimum number of bytes needed.
    pub fn finish(mut self) -> Vec<u8> {
        let byte_len = bits_to_bytes(self.bit_offset);
        self.buf.truncate(byte_len);
        self.buf
    }
}

// -- Varint -------------------------------------------------------------------

/// Maximum varint length for u64.
const MAX_VARINT_LEN: usize = 10;

/// Encode a u64 as a LEB128 varint (7 bits per byte, MSB = continuation).
/// Matches WebRTC's `EncodeVarInt`.
pub(crate) fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_VARINT_LEN);
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

// -- Helpers ------------------------------------------------------------------

fn bits_to_bytes(bits: usize) -> usize {
    (bits + 7) / 8
}

/// Bit width needed to represent `input` as an unsigned integer.
/// `UnsignedBitWidth(0)` = 1 (matching WebRTC's default behavior).
fn unsigned_bit_width(input: u64) -> u64 {
    if input == 0 {
        return 1;
    }
    64 - input.leading_zeros() as u64
}

/// Bit width needed for an unsigned value, but 0 maps to width 0.
/// Used in `SignedBitWidth` calculation.
fn unsigned_bit_width_zero_as_zero(input: u64) -> u64 {
    if input == 0 {
        return 0;
    }
    unsigned_bit_width(input)
}

/// Bit width needed for signed deltas given max positive and max negative magnitudes.
/// Matches WebRTC's `SignedBitWidth`.
fn signed_bit_width(max_pos_magnitude: u64, max_neg_magnitude: u64) -> u64 {
    let bitwidth_pos = unsigned_bit_width_zero_as_zero(max_pos_magnitude);
    let bitwidth_neg = if max_neg_magnitude > 0 {
        unsigned_bit_width_zero_as_zero(max_neg_magnitude - 1)
    } else {
        0
    };
    1 + std::cmp::max(bitwidth_pos, bitwidth_neg)
}

/// Maximum unsigned value for a given bit width.
fn max_unsigned_value_of_bit_width(bit_width: u64) -> u64 {
    debug_assert!((1..=64).contains(&bit_width));
    if bit_width == 64 {
        u64::MAX
    } else {
        (1u64 << bit_width) - 1
    }
}

/// Compute (current - previous) with wraparound at bit_mask.
fn unsigned_delta(previous: u64, current: u64, bit_mask: u64) -> u64 {
    current.wrapping_sub(previous) & bit_mask
}

// -- Header constants ---------------------------------------------------------

const BITS_ENCODING_TYPE: usize = 2;
const BITS_DELTA_WIDTH: usize = 6;
const BITS_SIGNED_DELTAS: usize = 1;
const BITS_VALUES_OPTIONAL: usize = 1;
const BITS_VALUE_WIDTH: usize = 6;

// -- Core encoder -------------------------------------------------------------

/// Encode a sequence of values using WebRTC's fixed-length bit-packed delta encoding.
///
/// `base` is the base value (from the proto's base field). If `None`, the field is
/// optional and the first present value is encoded as a varint.
///
/// `values` contains `number_of_deltas` values (one per subsequent event in the batch).
///
/// `value_width_bits` is the field-specific width controlling wrapping behavior.
/// For non-wrapping fields, pass 64.
///
/// Returns empty `Vec<u8>` if all values equal the base, signaling the caller
/// should NOT set the `_deltas` proto field (parser interprets missing field as "all equal").
pub(crate) fn encode_deltas(
    base: Option<u64>,
    values: &[Option<u64>],
    value_width_bits: u64,
) -> Vec<u8> {
    assert!(!values.is_empty());
    assert!((1..=64).contains(&value_width_bits));

    // Special case: all values identical to base → empty output.
    if values.iter().all(|v| *v == base) {
        return Vec::new();
    }

    // Determine if the sequence is non-decreasing and find max value
    let mut non_decreasing = true;
    let mut max_value_including_base = base.unwrap_or(0);
    let mut existent_count: usize = 0;
    {
        let mut previous = base.unwrap_or(0);
        for v in values {
            if let Some(val) = v {
                existent_count += 1;
                non_decreasing &= previous <= *val;
                max_value_including_base = std::cmp::max(max_value_including_base, *val);
                previous = *val;
            }
        }
    }

    // If non-decreasing, use value_width = 64 (no wrapping needed).
    // Otherwise compute the actual width from max value.
    let effective_value_width = if non_decreasing {
        64
    } else {
        std::cmp::max(unsigned_bit_width(max_value_including_base), value_width_bits)
    };

    let value_mask = max_unsigned_value_of_bit_width(effective_value_width);

    // Calculate min/max deltas
    let (max_unsigned_d, max_pos_signed_d, min_neg_signed_d) =
        calc_min_max_deltas(base, values, value_mask);

    let delta_width_unsigned = unsigned_bit_width(max_unsigned_d);
    let delta_width_signed = signed_bit_width(max_pos_signed_d, min_neg_signed_d);

    // Prefer unsigned if same width (efficiency)
    let signed_deltas = delta_width_signed < delta_width_unsigned;
    let delta_width_bits = if signed_deltas {
        delta_width_signed
    } else {
        delta_width_unsigned
    };

    let values_optional = !base.is_some() || existent_count < values.len();

    // Compute output size
    let header_bits = header_len_bits(signed_deltas, values_optional, effective_value_width);
    let delta_bits =
        encoded_deltas_len_bits(values, existent_count, base, delta_width_bits, values_optional);
    let total_bytes = bits_to_bytes(header_bits + delta_bits);

    let mut writer = BitWriter::with_capacity(total_bytes);
    let delta_mask = max_unsigned_value_of_bit_width(delta_width_bits);

    // Write header
    encode_header(
        &mut writer,
        delta_width_bits,
        signed_deltas,
        values_optional,
        effective_value_width,
    );

    // Write existence bitmap (if optional)
    if values_optional {
        for v in values {
            writer.write_bits(if v.is_some() { 1 } else { 0 }, 1);
        }
    }

    // Write deltas
    let mut previous = base;
    for v in values {
        let Some(val) = v else {
            continue;
        };

        if previous.is_none() {
            // First existent value when base is None → encode as varint
            let varint = encode_varint(*val);
            writer.write_bytes(&varint);
            // Pad remaining bytes of the varint allocation to maintain fixed output size
            for _ in varint.len()..MAX_VARINT_LEN {
                writer.write_bits(0, 8);
            }
        } else {
            let prev = previous.unwrap();
            if signed_deltas {
                encode_signed_delta(&mut writer, prev, *val, value_mask, delta_mask, delta_width_bits);
            } else {
                let delta = unsigned_delta(prev, *val, value_mask);
                writer.write_bits(delta, delta_width_bits as usize);
            }
        }

        previous = Some(*val);
    }

    writer.finish()
}

fn calc_min_max_deltas(
    base: Option<u64>,
    values: &[Option<u64>],
    bit_mask: u64,
) -> (u64, u64, u64) {
    let mut max_unsigned_delta = 0u64;
    let mut max_pos_signed_delta = 0u64;
    let mut min_neg_signed_delta = 0u64;

    let mut prev: Option<u64> = base;
    for v in values {
        let Some(val) = v else {
            continue;
        };

        if prev.is_none() {
            // First existent value when base is None: encoded as varint, not delta
            prev = Some(*val);
            continue;
        }

        let previous = prev.unwrap();
        let current = *val;

        let forward_delta = unsigned_delta(previous, current, bit_mask);
        let backward_delta = unsigned_delta(current, previous, bit_mask);

        max_unsigned_delta = std::cmp::max(max_unsigned_delta, forward_delta);

        if forward_delta < backward_delta {
            max_pos_signed_delta = std::cmp::max(max_pos_signed_delta, forward_delta);
        } else {
            min_neg_signed_delta = std::cmp::max(min_neg_signed_delta, backward_delta);
        }

        prev = Some(current);
    }

    (max_unsigned_delta, max_pos_signed_delta, min_neg_signed_delta)
}

fn header_len_bits(signed_deltas: bool, values_optional: bool, value_width_bits: u64) -> usize {
    if !signed_deltas && !values_optional && value_width_bits == 64 {
        // Compact header: encoding_type(2) + delta_width(6) = 8 bits
        BITS_ENCODING_TYPE + BITS_DELTA_WIDTH
    } else {
        // Full header: encoding_type(2) + delta_width(6) + signed(1) + optional(1) + value_width(6) = 16 bits
        BITS_ENCODING_TYPE + BITS_DELTA_WIDTH + BITS_SIGNED_DELTAS + BITS_VALUES_OPTIONAL + BITS_VALUE_WIDTH
    }
}

fn encoded_deltas_len_bits(
    values: &[Option<u64>],
    existent_count: usize,
    base: Option<u64>,
    delta_width_bits: u64,
    values_optional: bool,
) -> usize {
    if !values_optional {
        values.len() * delta_width_bits as usize
    } else {
        let existence_bitmap_bits = values.len();
        let first_is_varint = base.is_none() && existent_count >= 1;
        let varint_bits = if first_is_varint {
            8 * MAX_VARINT_LEN
        } else {
            0
        };
        let delta_count = existent_count - first_is_varint as usize;
        let delta_bits = delta_count * delta_width_bits as usize;
        existence_bitmap_bits + varint_bits + delta_bits
    }
}

fn encode_header(
    writer: &mut BitWriter,
    delta_width_bits: u64,
    signed_deltas: bool,
    values_optional: bool,
    value_width_bits: u64,
) {
    let use_compact = !signed_deltas && !values_optional && value_width_bits == 64;
    let encoding_type: u64 = if use_compact { 0 } else { 1 };

    writer.write_bits(encoding_type, BITS_ENCODING_TYPE);
    writer.write_bits(delta_width_bits - 1, BITS_DELTA_WIDTH);

    if use_compact {
        return;
    }

    writer.write_bits(signed_deltas as u64, BITS_SIGNED_DELTAS);
    writer.write_bits(values_optional as u64, BITS_VALUES_OPTIONAL);
    writer.write_bits(value_width_bits - 1, BITS_VALUE_WIDTH);
}

// -- Blob encoding (for RTCP raw packets) ------------------------------------

/// Encode variable-length blobs for RTCP raw packets.
///
/// Format (matches WebRTC's `blob_encoding.cc`):
///   Phase 1: For each blob, write `varint(length)`  — all lengths first
///   Phase 2: For each blob, write raw bytes          — all data concatenated
///
/// The decoder knows the blob count from `number_of_deltas` in the proto.
pub(crate) fn encode_blobs<T: AsRef<[u8]>>(blobs: &[T]) -> Vec<u8> {
    let total_len: usize = blobs
        .iter()
        .map(|b| {
            let b = b.as_ref();
            encode_varint(b.len() as u64).len() + b.len()
        })
        .sum();
    let mut out = Vec::with_capacity(total_len);

    // Phase 1: all lengths as varints
    for blob in blobs {
        let blob = blob.as_ref();
        out.extend(encode_varint(blob.len() as u64));
    }

    // Phase 2: all data concatenated
    for blob in blobs {
        out.extend_from_slice(blob.as_ref());
    }

    out
}

fn encode_signed_delta(
    writer: &mut BitWriter,
    previous: u64,
    current: u64,
    value_mask: u64,
    delta_mask: u64,
    delta_width_bits: u64,
) {
    let forward_delta = unsigned_delta(previous, current, value_mask);
    let backward_delta = unsigned_delta(current, previous, value_mask);

    let delta = if forward_delta <= backward_delta {
        forward_delta
    } else {
        // Two's complement negative in delta_width space
        delta_mask - backward_delta + 1
    };

    writer.write_bits(delta, delta_width_bits as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_encoding() {
        assert_eq!(encode_varint(0), vec![0x00]);
        assert_eq!(encode_varint(127), vec![0x7F]);
        assert_eq!(encode_varint(128), vec![0x80, 0x01]);
        assert_eq!(encode_varint(300), vec![0xAC, 0x02]);
    }

    #[test]
    fn unsigned_bit_width_values() {
        assert_eq!(unsigned_bit_width(0), 1);
        assert_eq!(unsigned_bit_width(1), 1);
        assert_eq!(unsigned_bit_width(2), 2);
        assert_eq!(unsigned_bit_width(3), 2);
        assert_eq!(unsigned_bit_width(4), 3);
        assert_eq!(unsigned_bit_width(255), 8);
        assert_eq!(unsigned_bit_width(256), 9);
        assert_eq!(unsigned_bit_width(u64::MAX), 64);
    }

    #[test]
    fn all_equal_returns_empty() {
        let base = Some(42u64);
        let values = vec![Some(42), Some(42), Some(42)];
        let result = encode_deltas(base, &values, 64);
        assert!(result.is_empty());
    }

    #[test]
    fn single_value_non_decreasing() {
        let base = Some(100u64);
        let values = vec![Some(102)];
        let result = encode_deltas(base, &values, 64);
        // Should produce compact header + 1 delta
        assert!(!result.is_empty());
    }

    #[test]
    fn roundtrip_simple_increasing() {
        // Sequence: base=100, values=[102, 104, 108]
        // Deltas: 2, 2, 4 → max_delta=4 → 3 bits unsigned
        let base = Some(100u64);
        let values = vec![Some(102), Some(104), Some(108)];
        let result = encode_deltas(base, &values, 64);
        assert!(!result.is_empty());
        // Non-decreasing → compact header (value_width=64)
        // Compact header = 8 bits: [00 000010] = encoding_type=0, delta_width=3-1=2
        // Deltas: 2 (010), 2 (010), 4 (100) = 9 bits → padded to byte boundary
        // Total: 8 + 9 = 17 bits → 3 bytes
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn optional_values_with_none_base() {
        let base: Option<u64> = None;
        let values = vec![Some(42), Some(44), None, Some(50)];
        let result = encode_deltas(base, &values, 64);
        assert!(!result.is_empty());
    }

    #[test]
    fn wrapping_sequence_number() {
        // 16-bit sequence numbers wrapping around
        let base = Some(65534u64);
        let values = vec![Some(65535), Some(0), Some(1)];
        let result = encode_deltas(base, &values, 16);
        assert!(!result.is_empty());
    }

    #[test]
    fn bit_writer_basics() {
        let mut w = BitWriter::with_capacity(2);
        w.write_bits(0b11, 2);
        w.write_bits(0b000101, 6);
        let out = w.finish();
        assert_eq!(out, vec![0b11000101]);
    }

    #[test]
    fn bit_writer_cross_byte() {
        let mut w = BitWriter::with_capacity(2);
        w.write_bits(0xFF, 8);
        w.write_bits(0b1010, 4);
        let out = w.finish();
        assert_eq!(out, vec![0xFF, 0b10100000]);
    }
}
