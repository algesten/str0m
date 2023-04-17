#![allow(missing_docs)]
#![allow(clippy::unusual_byte_groupings)]

use super::ext::{ExtensionMap, ExtensionValues};
use super::{Pt, SeqNo, Ssrc, MAX_BLANK_PADDING_PAYLOAD_SIZE};

/// Parsed header from an RTP packet.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    /// Always 2
    pub version: u8,
    /// Whether the RTP packet has padding to be an equal of 4 bytes.
    pub has_padding: bool,
    /// RTP packet has "RTP header extensions".
    pub has_extension: bool,
    // pub csrc_count: usize, // "contributing source" (other ssrc)
    /// A marker indicates the end of a series of packets belonging together such
    /// as for a single video frame.
    pub marker: bool,
    /// Type of payload being carried. What this correlates to is sent in the SDP.
    pub payload_type: Pt,
    /// Sequence number increasing by 1 for each RTP packet.
    pub sequence_number: u16,
    /// Timestamp in media time for the RTP packet. What the media time base is depends
    /// on the codec.
    pub timestamp: u32,
    /// Sender source identifier.
    pub ssrc: Ssrc,
    // pub csrc: [u32; 15],
    /// The extension values parsed using the mapping via SDP.
    pub ext_vals: ExtensionValues,
    /// Length of header.
    pub header_len: usize,
}

impl RtpHeader {
    pub fn write_to(&self, buf: &mut [u8], exts: &ExtensionMap) -> usize {
        buf[0] = 0b10_0_0_0000
            | if self.has_padding { 1 << 5 } else { 0 }
            | if self.has_extension { 1 << 4 } else { 0 };

        assert!(*self.payload_type <= 127);
        buf[1] = *self.payload_type & 0b0111_1111 | if self.marker { 1 << 7 } else { 0 };

        buf[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

        buf[12..14].copy_from_slice(&0xbede_u16.to_be_bytes());

        let ext_buf = &mut buf[16..];
        let mut ext_len = exts.write_to(ext_buf, &self.ext_vals);

        let pad = 4 - ext_len % 4;
        if pad < 4 {
            ext_len += pad;
            for i in 0..pad {
                ext_buf[ext_len - i - 1] = 0;
            }
        }

        let bede_len = (ext_len / 4) as u16;
        buf[14..16].copy_from_slice(&bede_len.to_be_bytes());

        16 + ext_len
    }

    pub fn pad_packet(
        buf: &mut [u8],
        header_len: usize,
        body_len: usize,
        block_size: usize,
    ) -> usize {
        let pad = block_size - body_len % block_size;
        if pad == block_size {
            return 0;
        }

        let len = header_len + body_len;

        #[allow(clippy::needless_range_loop)]
        for i in len..(len + pad) {
            buf[i] = 0;
        }
        buf[len + pad - 1] = pad as u8;

        // set the padding bit
        buf[0] |= 0b00_1_0_0000;

        pad
    }

    /// Write a packet consisting entirely of padding and write.
    pub fn create_padding_packet(
        buf: &mut [u8],
        pad_len: u8,
        header_len: usize,
        block_size: usize,
    ) -> usize {
        if pad_len == 0 {
            warn!("Not generating padding packet with zero length");
            return 0;
        }

        let rounded_len = if pad_len as usize % block_size == 0 {
            pad_len as usize
        } else {
            ((pad_len as usize / block_size) + 1) * block_size
        }
        .min(MAX_BLANK_PADDING_PAYLOAD_SIZE);

        for i in 0..rounded_len.saturating_sub(1) {
            buf[header_len + i] = 0;
        }
        buf[header_len + rounded_len.saturating_sub(1)] = rounded_len as u8;

        // set the padding bit
        buf[0] |= 0b00_1_0_0000;

        rounded_len
    }

    pub fn parse(buf: &[u8], exts: &ExtensionMap) -> Option<RtpHeader> {
        let orig_len = buf.len();
        if buf.len() < 12 {
            trace!("RTP header too short < 12: {}", buf.len());
            return None;
        }

        let version = (buf[0] & 0b1100_0000) >> 6;
        if version != 2 {
            trace!("RTP version is not 2");
            return None;
        }
        let has_padding = buf[0] & 0b0010_0000 > 0;
        let has_extension = buf[0] & 0b0001_0000 > 0;
        let csrc_count = (buf[0] & 0b0000_1111) as usize;
        let marker = buf[1] & 0b1000_0000 > 0;
        let payload_type = (buf[1] & 0b0111_1111).into();
        let sequence_number = u16::from_be_bytes([buf[2], buf[3]]);

        let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        // use once_cell::sync::Lazy;
        // use std::collections::HashMap;
        // use std::sync::Mutex;
        // use std::time::Instant;
        // static FIRST: Lazy<Mutex<HashMap<u32, (Instant, u32)>>> =
        //     Lazy::new(|| Mutex::new(HashMap::new()));
        // let mut lock = FIRST.lock().unwrap();
        // if let Some((t, m)) = lock.get_mut(&ssrc) {
        //     let tdelta = Instant::now() - *t;
        //     let mdelta = (timestamp as f64 - *m as f64) / 90_000.0;
        //     println!("{} {}", ssrc, tdelta.as_secs_f64() - mdelta);
        // } else {
        //     lock.insert(ssrc, (Instant::now(), timestamp));
        // }

        let buf: &[u8] = &buf[12..];

        let csrc_len = 4 * csrc_count;
        if buf.len() < csrc_len {
            trace!("RTP header invalid, not enough csrc");
            return None;
        }

        let mut csrc = [0_u32; 15];
        for i in 0..csrc_count {
            let n = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
            csrc[i] = n;
        }

        let buf: &[u8] = &buf[csrc_len..];

        let mut ext = ExtensionValues {
            ..Default::default()
        };

        let rest = if !has_extension {
            buf
        } else {
            if buf.len() < 4 {
                trace!("RTP bad header extension");
                return None;
            }

            let ext_type = u16::from_be_bytes([buf[0], buf[1]]);
            let ext_words = u16::from_be_bytes([buf[2], buf[3]]);
            let ext_len = ext_words as usize * 4;

            let buf: &[u8] = &buf[4..];

            if buf.len() < ext_len {
                trace!("RTP ext len larger than header {} > {}", buf.len(), ext_len);
                return None;
            }

            if ext_type == 0xbede {
                // each media has a specific extmap mapping.
                exts.parse(&buf[..ext_len], &mut ext);
            }

            &buf[ext_len..]
        };

        let header_len = orig_len - rest.len();

        let ret = RtpHeader {
            version,
            has_padding,
            has_extension,
            // csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc: ssrc.into(),
            // csrc,
            ext_vals: ext,
            header_len,
        };

        Some(ret)
    }

    /// For RTX the original sequence number is inserted before the RTP payload.
    pub fn read_original_sequence_number(buf: &[u8], seq_no: &mut u16) -> usize {
        *seq_no = u16::from_be_bytes([buf[0], buf[1]]);
        2
    }

    /// For RTX the original sequence number is inserted before the RTP payload.
    pub fn write_original_sequence_number(buf: &mut [u8], seq_no: SeqNo) -> usize {
        let seq_u16 = (*seq_no) as u16;
        buf[0..2].copy_from_slice(&seq_u16.to_be_bytes());
        2
    }

    pub fn is_rtx_null_packet(buf: &[u8]) -> bool {
        if buf.len() < 10 {
            return false;
        }
        buf[0..10] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    /// Sequencer number of this RTP header given the previous number.
    ///
    /// The logic detects wrap-arounds of the 16-bit RTP sequence number.
    pub fn sequence_number(&self, previous: Option<SeqNo>) -> SeqNo {
        let e_seq = extend_u16(previous.map(|v| *v), self.sequence_number);
        e_seq.into()
    }
}

macro_rules! mk_extend {
    ($id:ident, $t:ty) => {
        /// "extend" a less than 64 bit sequence number into a 64 bit by
        /// using the knowledge of the previous such sequence number.
        pub fn $id(prev_ext_seq: Option<u64>, seq: $t) -> u64 {
            use std::mem;
            const MAX: u64 = <$t>::MAX as u64 + 1; // u16: 65_536;
            const HALF: u64 = MAX / 2; // u16: 32_768
            const BITS: usize = mem::size_of::<$t>() * 8;
            const ROC_MASK: i64 = (u64::MAX >> BITS) as i64;

            // We define the index of the SRTP packet corresponding to a given
            // ROC and RTP sequence number to be the 48-bit quantity
            //       i = 2^16 * ROC + SEQ.
            //
            // https://tools.ietf.org/html/rfc3711#appendix-A
            //
            let seq = seq as u64;

            if prev_ext_seq.is_none() {
                // No wrap-around so far.
                return seq;
            }

            let prev_index = prev_ext_seq.unwrap();
            let roc = (prev_index >> BITS) as i64; // how many wrap-arounds.
            let prev_seq = prev_index & (MAX - 1); // u16: 0xffff

            let v = if prev_seq < HALF {
                if seq > HALF + prev_seq {
                    (roc - 1) & ROC_MASK
                } else {
                    roc
                }
            } else if prev_seq > seq + HALF {
                (roc + 1) & ROC_MASK
            } else {
                roc
            };

            if v < 0 {
                return 0;
            }

            (v as u64) * MAX + seq
        }
    };
}

mk_extend!(extend_u16, u16);
mk_extend!(extend_u32, u32);

impl Default for RtpHeader {
    fn default() -> Self {
        Self {
            version: 2,
            has_padding: false,
            has_extension: true,
            marker: false,
            payload_type: 1.into(),
            sequence_number: 0,
            timestamp: 0,
            ssrc: 0.into(),
            ext_vals: ExtensionValues::default(),
            header_len: 16,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::rtp::{Extension, MediaTime};

    use super::*;

    #[test]
    fn extend_u16_wrap_around() {
        assert_eq!(extend_u16(None, 0), 0);
        assert_eq!(extend_u16(Some(0), 1), 1);
        assert_eq!(extend_u16(Some(65_535), 0), 65_536);
        assert_eq!(extend_u16(Some(65_500), 2), 65_538);
        assert_eq!(extend_u16(Some(2), 1), 1);
        assert_eq!(extend_u16(Some(65_538), 1), 65_537);
        assert_eq!(extend_u16(Some(3), 3), 3);
        assert_eq!(extend_u16(Some(65_500), 65_500), 65_500);
    }

    #[test]
    fn extend_u16_with_0_prev() {
        // This tests going backwards from previous 0. This should wrap
        // around "backwards" making a ridiculous number.
        let seq = u16::MAX / 2 + 2;
        let expected = u64::MAX - (u16::MAX - seq) as u64;
        assert_eq!(extend_u16(Some(0), seq), expected);
    }

    #[test]
    fn extend_u32_wrap_around() {
        const U32MAX: u64 = u32::MAX as u64 + 1;
        assert_eq!(extend_u32(None, 0), 0);
        assert_eq!(extend_u32(Some(0), 1), 1);
        assert_eq!(extend_u32(Some(U32MAX - 1), 0), U32MAX);
        assert_eq!(extend_u32(Some(U32MAX - 32), 2), U32MAX + 2);
        assert_eq!(extend_u32(Some(2), 1), 1);
        assert_eq!(extend_u32(Some(U32MAX + 2), 1), U32MAX + 1);
        assert_eq!(extend_u32(Some(3), 3), 3);
        assert_eq!(
            extend_u32(Some(U32MAX - 32), (U32MAX - 32) as u32),
            U32MAX - 32
        );
    }

    #[test]
    fn extend_u32_with_0_prev() {
        // This tests going backwards from previous 0. This should wrap
        // around "backwards" making a ridiculous number.
        let seq = u32::MAX / 2 + 2;
        let expected = u64::MAX - (u32::MAX - seq) as u64;
        assert_eq!(extend_u32(Some(0), seq), expected);
    }

    #[test]
    fn test_generate_one_length_padding_packet() {
        let mut buf = vec![6; 255];
        RtpHeader::create_padding_packet(&mut buf, 1, 10, 16);

        let mut expected = vec![0; 16];
        expected[15] = 16;
        assert_eq!(&buf[10..26], &expected);
    }

    // version: 2,
    // has_padding: false,
    // has_extension: true,
    // marker: false,
    // payload_type: 1.into(),
    // sequence_number: 0,
    // timestamp: 0,
    // ssrc: 0.into(),
    // ext_vals: ExtensionValues::default(),
    // header_len: 16,

    #[test]
    fn test_write_rtp_headers() {
        fn mk_header(seq: u16, ts: u32, level: i8, marker: bool, exts: &ExtensionMap) -> Vec<u8> {
            let header = RtpHeader {
                payload_type: 33.into(),
                sequence_number: seq,
                timestamp: ts,
                ssrc: 44.into(),
                marker,
                ext_vals: ExtensionValues {
                    audio_level: Some(level),
                    voice_activity: Some(false),
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut buf = vec![0; 2000];
            let n = header.write_to(&mut buf[..], exts);
            buf.truncate(n);

            buf
        }

        let mut exts = ExtensionMap::empty();
        exts.set(3, Extension::AudioLevel);

        let buf1 = mk_header(47_000, 10_000, -42, false, &exts);
        let buf2 = mk_header(47_001, 12_000, -43, true, &exts);
        let buf3 = mk_header(47_002, 14_000, -44, false, &exts);

        let p1 = &[
            144, 33, 183, 152, 0, 0, 39, 16, 0, 0, 0, 44, 190, 222, 0, 1, 48, 170, 0, 0,
        ];
        let p2 = &[
            144, 161, 183, 153, 0, 0, 46, 224, 0, 0, 0, 44, 190, 222, 0, 1, 48, 171, 0, 0,
        ];
        let p3 = &[
            144, 33, 183, 154, 0, 0, 54, 176, 0, 0, 0, 44, 190, 222, 0, 1, 48, 172, 0, 0,
        ];

        assert_eq!(&buf1, p1);
        assert_eq!(&buf2, p2);
        assert_eq!(&buf3, p3);
    }

    #[test]
    fn test_parse_rtp_headers() {
        let exts = ExtensionMap::standard();

        let hb1 = [
            176, 111, 183, 152, 0, 0, 39, 16, 46, 87, 21, 249, 190, 222, 0, 4, 16, 170, 34, 254,
            32, 106, 49, 0, 0, 66, 120, 89, 106, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 12,
        ];

        let hb2 = [
            176, 111, 183, 153, 0, 0, 46, 224, 46, 87, 21, 249, 190, 222, 0, 4, 16, 171, 34, 254,
            134, 208, 49, 0, 2, 66, 120, 89, 106, 0, 0, 0, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 12,
        ];
        let hb3 = [
            176, 111, 183, 154, 0, 0, 54, 176, 46, 87, 21, 249, 190, 222, 0, 4, 16, 172, 34, 254,
            32, 106, 49, 0, 1, 66, 120, 89, 106, 0, 0, 0, 9, 10, 11, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 12,
        ];

        let h1 = RtpHeader::parse(&hb1, &exts).unwrap();
        assert_eq!(
            h1,
            RtpHeader {
                version: 2,
                has_padding: true,
                has_extension: true,
                marker: false,
                payload_type: 111.into(),
                sequence_number: 47000,
                timestamp: 10000,
                ssrc: 777459193.into(),
                ext_vals: ExtensionValues {
                    mid: Some("xYj".into()),
                    abs_send_time: Some(MediaTime::new(16654442, 262144)),
                    voice_activity: Some(true),
                    audio_level: Some(-42),
                    transport_cc: Some(0),
                    ..Default::default()
                },
                header_len: 32
            }
        );

        let h2 = RtpHeader::parse(&hb2, &exts).unwrap();
        assert_eq!(
            h2,
            RtpHeader {
                version: 2,
                has_padding: true,
                has_extension: true,
                marker: false,
                payload_type: 111.into(),
                sequence_number: 47001,
                timestamp: 12000,
                ssrc: 777459193.into(),
                ext_vals: ExtensionValues {
                    mid: Some("xYj".into()),
                    abs_send_time: Some(MediaTime::new(16680656, 262144)),
                    voice_activity: Some(true),
                    audio_level: Some(-43),
                    transport_cc: Some(2),
                    ..Default::default()
                },
                header_len: 32
            }
        );

        let h3 = RtpHeader::parse(&hb3, &exts).unwrap();
        assert_eq!(
            h3,
            RtpHeader {
                version: 2,
                has_padding: true,
                has_extension: true,
                marker: false,
                payload_type: 111.into(),
                sequence_number: 47002,
                timestamp: 14000,
                ssrc: 777459193.into(),
                ext_vals: ExtensionValues {
                    mid: Some("xYj".into()),
                    abs_send_time: Some(MediaTime::new(16654442, 262144)),
                    voice_activity: Some(true),
                    audio_level: Some(-44),
                    transport_cc: Some(1),
                    ..Default::default()
                },
                header_len: 32
            }
        );
    }
}
