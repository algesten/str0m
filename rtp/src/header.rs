use crate::ext::{ExtensionValues, Extensions};
use crate::{MediaTime, Pt, SeqNo, Ssrc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    pub version: u8,
    pub has_padding: bool,
    pub has_extension: bool,
    // pub csrc_count: usize, // "contributing source" (other ssrc)
    pub marker: bool,
    pub payload_type: Pt,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: Ssrc,
    // pub csrc: [u32; 15],
    pub ext_vals: ExtensionValues,
    pub header_len: usize,
}

impl RtpHeader {
    pub fn new(pt: Pt, seq_no: SeqNo, ts: MediaTime, ssrc: Ssrc) -> Self {
        RtpHeader {
            version: 2,
            has_padding: false,
            has_extension: true,
            marker: false,
            payload_type: pt,
            sequence_number: *seq_no as u16,
            timestamp: ts.as_ntp_32(),
            ssrc,
            ext_vals: ExtensionValues::default(),
            header_len: 16,
        }
    }

    pub fn write_to(&self, buf: &mut [u8], exts: &Extensions) -> usize {
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
        let pad = if pad == block_size { 0 } else { pad };

        let len = header_len + body_len;

        for i in len..(len + pad) {
            buf[i] = 0;
        }
        buf[len + pad - 1] = pad as u8;

        if pad > 0 {
            // set the padding bit
            buf[0] |= 0b00_1_0_0000;
        }

        pad
    }

    pub fn parse(buf: &[u8], exts: &Extensions) -> Option<RtpHeader> {
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

        let ssrc = (u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]])).into();

        let buf: &[u8] = &buf[12..];

        let csrc_len = 4 * csrc_count as usize;
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
                // each m-line has a specific extmap mapping.
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
            ssrc,
            // csrc,
            ext_vals: ext,
            header_len,
        };

        Some(ret)
    }

    /// For RTX the original sequence number is inserted befor the RTP payload.
    pub fn read_original_sequence_number(buf: &[u8], seq_no: &mut u16) -> usize {
        *seq_no = u16::from_be_bytes([buf[0], buf[1]]);
        2
    }

    /// For RTX the original sequence number is inserted befor the RTP payload.
    pub fn write_original_sequence_number(buf: &mut [u8], seq_no: SeqNo) -> usize {
        let seq_u16 = (*seq_no) as u16;
        buf[0..2].copy_from_slice(&seq_u16.to_be_bytes());
        2
    }

    pub fn is_rtx_null_packet(buf: &[u8]) -> bool {
        &buf[0..10] == &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    /// Sequencer number of this RTP header given the previous number.
    ///
    /// The logic detects wrap-arounds of the 16-bit RTP sequence number.
    pub fn sequence_number(&self, previous: Option<SeqNo>) -> SeqNo {
        let e_seq = extend_seq(previous.map(|v| *v), self.sequence_number);
        e_seq.into()
    }
}

/// "extend" a 16 bit sequence number into a 64 bit by
/// using the knowledge of the previous such sequence number.
pub fn extend_seq(prev_ext_seq: Option<u64>, seq: u16) -> u64 {
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
    let roc = prev_index >> 16; // how many wrap-arounds.
    let prev_seq = prev_index & 0xffff;

    let v = if prev_seq < 32_768 {
        if seq > 32_768 + prev_seq {
            (roc - 1) & 0xffff_ffff
        } else {
            roc
        }
    } else {
        if prev_seq > seq + 32_768 {
            (roc + 1) & 0xffff_ffff
        } else {
            roc
        }
    };

    v * 65_536 + (seq as u64)
}

// /// Determine number of packets expected and lost.
// impl IngressStream {
//     pub fn determine_loss(&mut self) {
//         // https://tools.ietf.org/html/rfc3550#appendix-A.3
//         let expected = (self.rtp_max_seq - self.rtp_start_seq + 1) as i64;
//         let received = self.rtp_packet_count as i64;
//         let lost = expected - received;

//         let mut fract = 0;

//         if self.rtp_packets_expected_prior != 0 && self.rtp_packets_received_prior != 0 {
//             let expected_interval = self.rtp_packets_expected_prior - expected;
//             let received_interval = self.rtp_packets_received_prior - received;

//             let lost_interval = expected_interval - received_interval;

//             if expected_interval == 0 || lost_interval <= 0 {
//                 fract = 0;
//             } else {
//                 fract = (lost_interval << 8) / expected_interval;
//             }
//         }

//         self.rtp_packets_expected_prior = expected;
//         self.rtp_packets_received_prior = received;
//         self.rtp_lost_packets = lost;
//         self.rtp_packet_loss = fract as f32 / 255.0;
//     }

//     pub fn estimate_jitter(&mut self, sys_time: Ts, rtp_time: Ts) {
//         // https://tools.ietf.org/html/rfc3550#appendix-A.8
//         let rtp_timebase = rtp_time.denum();

//         if !self.rtp_sys_time_prior.is_zero() {
//             let transit = sys_time - rtp_time;
//             let transit_prior = self.rtp_sys_time_prior - self.rtp_time_prior;
//             let d = (transit - transit_prior).abs().rebase(rtp_timebase);

//             self.rtp_jitter += 1.0 / 16.0 * (d.numer() as f64 - self.rtp_jitter);
//             self.rtp_jitter_norm = self.rtp_jitter / rtp_timebase as f64;
//         }

//         self.rtp_sys_time_prior = sys_time;
//         self.rtp_time_prior = rtp_time;
//     }
// }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn extend_seq_wrap_around() {
        assert_eq!(extend_seq(None, 0), 0);
        assert_eq!(extend_seq(Some(0), 1), 1);
        assert_eq!(extend_seq(Some(65_535), 0), 65_536);
        assert_eq!(extend_seq(Some(65_500), 2), 65_538);
        assert_eq!(extend_seq(Some(2), 1), 1);
        assert_eq!(extend_seq(Some(65_538), 1), 65_537);
        assert_eq!(extend_seq(Some(3), 3), 3);
        assert_eq!(extend_seq(Some(65_500), 65_500), 65_500);
    }
}
