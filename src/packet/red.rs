//! RFC 2198 "RTP Payload for Redundant Audio Data" (RED) encode/decode.
//!
//! The RED structure is part of the RTP payload (so it is fully covered by SRTP): N redundant
//! block headers (4 bytes each, F=1: 7-bit PT, 14-bit timestamp offset, 10-bit length), then the
//! primary block header (1 byte, F=0: 7-bit PT), then all block payloads in the same order.

use super::PacketError;

const F_BIT: u8 = 0x80;

/// Largest representable timestamp offset (14-bit field).
const MAX_TS_OFFSET: u32 = 0x3fff;

/// Largest representable redundant block length (10-bit field).
const MAX_BLOCK_LEN: usize = 0x3ff;

/// Maximum redundant blocks accepted in one RED payload. RFC 2198 sets no limit, but real
/// Opus-RED senders use a single level of redundancy (str0m sends one; libwebrtc defaults to one
/// and its receiver caps at 32). A 4-byte redundant header can otherwise pack hundreds of blocks
/// into one datagram, so reject more than this to bound the parse work a malformed or hostile
/// peer can trigger.
const MAX_REDUNDANT_BLOCKS: usize = 32;

/// How many levels of redundancy we recover from on receive. str0m sends one; this leaves a small
/// margin for shallow multi-level senders while bounding the per-packet recovery work (decode +
/// depayload) a hostile peer can trigger, independent of how many blocks the payload carries.
const MAX_RED_RECOVERY_DEPTH: u64 = 2;

/// A redundant block to prepend to the primary payload (older media).
#[derive(Debug, Clone)]
pub struct RedundantBlock {
    /// Block payload type (7-bit).
    pub pt: u8,
    /// `primary_rtp_timestamp - block_timestamp`, 14-bit (max 16383).
    pub timestamp_offset: u32,
    /// Block payload bytes, 10-bit length (max 1023).
    pub payload: Vec<u8>,
}

impl RedundantBlock {
    /// Whether this block fits RFC 2198's 14-bit offset and 10-bit length fields.
    pub fn fits(&self) -> bool {
        self.timestamp_offset <= MAX_TS_OFFSET && self.payload.len() <= MAX_BLOCK_LEN
    }
}

/// A block parsed out of a RED payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedBlock<'a> {
    /// Block payload type (7-bit).
    pub pt: u8,
    /// Timestamp offset from the primary (0 for the primary block).
    pub timestamp_offset: u32,
    /// Block payload bytes (no header).
    pub payload: &'a [u8],
    /// Whether this is the primary (final) block.
    pub is_primary: bool,
}

/// Encoder for RFC 2198 RED payloads.
pub struct RedEncoder;

impl RedEncoder {
    /// Encode a RED payload: redundant blocks (oldest first) followed by the primary block.
    ///
    /// Redundant blocks whose offset or length do not fit RFC 2198's 14-bit / 10-bit fields are
    /// skipped (see [`RedundantBlock::fits`]) so the output is always a valid RED payload, never
    /// silently truncated.
    pub fn encode(primary_pt: u8, primary: &[u8], redundant: &[RedundantBlock]) -> Vec<u8> {
        let blocks: Vec<&RedundantBlock> = redundant.iter().filter(|b| b.fits()).collect();

        let mut out = Vec::with_capacity(primary.len() + blocks.len() * 4 + 1);

        for b in &blocks {
            // `fits()` guarantees ts <= 0x3fff and len <= 0x3ff, so no masking is needed.
            let ts = b.timestamp_offset;
            let len = b.payload.len() as u32;
            out.push(F_BIT | (b.pt & 0x7f));
            out.push((ts >> 6) as u8);
            out.push((((ts & 0x3f) << 2) | (len >> 8)) as u8);
            out.push((len & 0xff) as u8);
        }

        // Primary header, F=0.
        out.push(primary_pt & 0x7f);

        for b in &blocks {
            out.extend_from_slice(&b.payload);
        }
        out.extend_from_slice(primary);

        out
    }
}

/// Decoder for RFC 2198 RED payloads.
pub struct RedDecoder;

impl RedDecoder {
    /// Parse a RED payload into its blocks (redundant first, primary last).
    ///
    /// Never panics; returns `Err` on any malformed input. RED payloads come from untrusted
    /// remote peers, so this strictly validates header chaining and block lengths.
    pub fn decode(data: &[u8]) -> Result<Vec<RedBlock<'_>>, PacketError> {
        struct Hdr {
            pt: u8,
            ts_offset: u32,
            len: Option<usize>,
        }

        // Phase 1: parse headers up to and including the primary (F=0) header.
        let mut hdrs: Vec<Hdr> = Vec::new();
        let mut i = 0;
        loop {
            let first = *data.get(i).ok_or(PacketError::ErrRedCorruptedPacket)?;
            if first & F_BIT == 0 {
                hdrs.push(Hdr {
                    pt: first & 0x7f,
                    ts_offset: 0,
                    len: None,
                });
                i += 1;
                break;
            }
            // Bound the redundant blocks (untrusted input) before parsing/allocating more. At this
            // point `hdrs` holds only redundant headers, since the primary (F=0) breaks the loop.
            if hdrs.len() >= MAX_REDUNDANT_BLOCKS {
                return Err(PacketError::ErrRedCorruptedPacket);
            }
            let h = data
                .get(i..i + 4)
                .ok_or(PacketError::ErrRedCorruptedPacket)?;
            let ts_offset = ((h[1] as u32) << 6) | ((h[2] as u32) >> 2);
            let len = (((h[2] as usize) & 0x03) << 8) | (h[3] as usize);
            hdrs.push(Hdr {
                pt: h[0] & 0x7f,
                ts_offset,
                len: Some(len),
            });
            i += 4;
        }

        // Phase 2: slice the payloads in the same order as the headers.
        let mut out = Vec::with_capacity(hdrs.len());
        for h in &hdrs {
            match h.len {
                Some(len) => {
                    let payload = data
                        .get(i..i + len)
                        .ok_or(PacketError::ErrRedCorruptedPacket)?;
                    out.push(RedBlock {
                        pt: h.pt,
                        timestamp_offset: h.ts_offset,
                        payload,
                        is_primary: false,
                    });
                    i += len;
                }
                None => {
                    // Primary block takes the remaining bytes (may be empty).
                    out.push(RedBlock {
                        pt: h.pt,
                        timestamp_offset: 0,
                        payload: &data[i..],
                        is_primary: true,
                    });
                }
            }
        }

        Ok(out)
    }
}

/// Select the redundant blocks to attempt recovery from, given the decoded redundant blocks
/// (oldest first) and the primary payload type.
///
/// Returns `(distance_back, block)` pairs, where `distance_back` is how many sequence numbers
/// before the primary the block sits (1 = the immediately preceding packet). Only the most-recent
/// [`MAX_RED_RECOVERY_DEPTH`] blocks that carry `primary_pt` are returned: RFC 2198 allows a
/// redundant block to use a different PT, and str0m only recovers the primary (Opus) codec, so
/// blocks of another PT are skipped; bounding the depth caps the recovery work a hostile peer can
/// trigger regardless of how many blocks the payload packs.
pub(crate) fn red_recovery_blocks<'a>(
    redundant: &'a [RedBlock<'a>],
    primary_pt: u8,
) -> Vec<(u64, &'a RedBlock<'a>)> {
    let n = redundant.len() as u64;
    redundant
        .iter()
        .enumerate()
        .map(|(i, b)| (n - i as u64, b))
        .filter(|(back, b)| *back <= MAX_RED_RECOVERY_DEPTH && b.pt == primary_pt)
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn primary_only_roundtrip() {
        let bytes = RedEncoder::encode(96, &[1, 2, 3], &[]);
        assert_eq!(bytes, vec![96, 1, 2, 3]);

        let blocks = RedDecoder::decode(&bytes).unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].is_primary);
        assert_eq!(blocks[0].pt, 96);
        assert_eq!(blocks[0].timestamp_offset, 0);
        assert_eq!(blocks[0].payload, &[1, 2, 3]);
    }

    #[test]
    fn one_redundant_block_roundtrip() {
        let red = [RedundantBlock {
            pt: 96,
            timestamp_offset: 960,
            payload: vec![9, 9],
        }];
        let bytes = RedEncoder::encode(96, &[1, 2, 3], &red);

        // Redundant header for ts_offset=960, len=2: F|pt=0xE0; 960>>6=15, low-6 ts bits and the
        // 2 high len bits are 0, len low byte = 2.
        assert_eq!(&bytes[..4], &[0xE0, 15, 0, 2]);
        assert_eq!(bytes[4], 96); // primary header, F=0
        assert_eq!(&bytes[5..], &[9, 9, 1, 2, 3]); // redundant payload then primary

        let blocks = RedDecoder::decode(&bytes).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(!blocks[0].is_primary);
        assert_eq!(blocks[0].timestamp_offset, 960);
        assert_eq!(blocks[0].payload, &[9, 9]);
        assert!(blocks[1].is_primary);
        assert_eq!(blocks[1].payload, &[1, 2, 3]);
    }

    #[test]
    fn encode_skips_oversized_blocks() {
        // A block whose offset (>14 bits) or length (>10 bits) does not fit is dropped, so the
        // wire payload is never silently corrupted — even in release builds.
        let bad_offset = RedundantBlock {
            pt: 96,
            timestamp_offset: 0x4000, // > 0x3fff
            payload: vec![1, 2],
        };
        let bad_len = RedundantBlock {
            pt: 96,
            timestamp_offset: 100,
            payload: vec![0u8; 2000], // > 0x3ff
        };
        let bytes = RedEncoder::encode(96, &[7, 7], &[bad_offset, bad_len]);

        let blocks = RedDecoder::decode(&bytes).unwrap();
        assert_eq!(blocks.len(), 1, "oversized blocks must be skipped");
        assert!(blocks[0].is_primary);
        assert_eq!(blocks[0].payload, &[7, 7]);
    }

    #[test]
    fn truncated_header_is_error_not_panic() {
        assert!(RedDecoder::decode(&[0x80, 0x00]).is_err()); // F=1 but < 4 header bytes
        assert!(RedDecoder::decode(&[]).is_err()); // empty
    }

    #[test]
    fn block_length_past_end_is_error() {
        // redundant header claims len=200 (len hi byte 0, lo byte 200) but no payload follows
        let b = [0x80 | 96, 0, 0, 200, 96];
        assert!(RedDecoder::decode(&b).is_err());
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // Exhaustively poke short inputs; the decoder must only ever return Ok/Err.
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let _ = RedDecoder::decode(&[a as u8, b as u8]);
            }
        }
    }

    #[test]
    fn decode_rejects_too_many_redundant_blocks() {
        // One 4-byte redundant header per block lets a single datagram pack hundreds of blocks.
        // The decoder must bound this so a hostile peer can't expand one packet into an unbounded
        // number of recovered packets. `n` zero-length redundant blocks, then an empty primary.
        fn red_with_redundant_blocks(n: usize) -> Vec<u8> {
            let mut data = Vec::with_capacity(n * 4 + 1);
            for _ in 0..n {
                data.extend_from_slice(&[F_BIT | 96, 0, 0, 0]); // F=1, pt=96, ts=0, len=0
            }
            data.push(96); // primary header, F=0
            data
        }

        // At the limit: MAX redundant + 1 primary still decodes.
        let ok = red_with_redundant_blocks(MAX_REDUNDANT_BLOCKS);
        let blocks = RedDecoder::decode(&ok).expect("max redundant blocks is allowed");
        assert_eq!(blocks.len(), MAX_REDUNDANT_BLOCKS + 1);

        // One over the limit, and a pathological count, are rejected (not decoded).
        assert!(RedDecoder::decode(&red_with_redundant_blocks(MAX_REDUNDANT_BLOCKS + 1)).is_err());
        assert!(RedDecoder::decode(&red_with_redundant_blocks(360)).is_err());
    }

    #[test]
    fn recovery_blocks_caps_depth_and_filters_pt() {
        // Oldest-first redundant blocks; primary PT is 111. Index 1 carries a different PT and
        // must be skipped; only the most-recent MAX_RED_RECOVERY_DEPTH same-PT blocks are kept,
        // each with the correct distance-back (1 = immediately preceding packet).
        let block = |pt| RedBlock {
            pt,
            timestamp_offset: 0,
            payload: &[0u8],
            is_primary: false,
        };
        let redundant = vec![block(111), block(96), block(111), block(111), block(111)];

        let got = red_recovery_blocks(&redundant, 111);

        let backs: Vec<u64> = got.iter().map(|(back, _)| *back).collect();
        assert_eq!(backs, vec![2, 1], "only the two most-recent same-PT blocks");
        assert!(got.iter().all(|(_, b)| b.pt == 111));

        // A block list whose recent blocks are all a foreign PT yields nothing to recover.
        let foreign = vec![block(111), block(96), block(96)];
        assert!(red_recovery_blocks(&foreign, 111).is_empty());
    }
}
