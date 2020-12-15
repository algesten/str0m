use crate::error::Error;
use crate::media::IngressStream;
use crate::sdp::{ExtMap, RtpExtensionType};
use crate::{error::ErrorKind, util::Ts};
use std::fmt;
use std::str::from_utf8;

#[derive(Debug, Clone)]
pub struct RtpHeader<'a> {
    pub version: u8,
    pub has_padding: bool,
    pub has_extension: bool,
    // pub csrc_count: usize, // "contributing source" (other ssrc)
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    // pub csrc: [u32; 15],
    pub ext: RtpExtValues<'a>,
    pub header_len: usize,
}

pub fn parse_header<'a>(buf: &'a [u8], id_to_ext: &IdToExtType) -> Option<RtpHeader<'a>> {
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
    let payload_type = buf[1] & 0b0111_1111;
    let sequence_number = u16::from_be_bytes([buf[2], buf[3]]);

    let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

    let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

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

    let mut ext = RtpExtValues {
        ..Default::default()
    };

    let rest = if !has_extension {
        buf
    } else {
        if buf.len() < 4 {
            trace!("RTP bad header extension");
            return None;
        }

        let ext_type = u32::from_be_bytes([0, 0, buf[0], buf[1]]);
        let ext_words = u32::from_be_bytes([0, 0, buf[2], buf[3]]);
        let ext_len = ext_words as usize * 4;

        let buf: &[u8] = &buf[4..];
        if ext_type == 0xbede {
            // each m-line has a specific extmap mapping.
            parse_bede(&buf[..ext_len], &mut ext, id_to_ext);
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
        ext,
        header_len,
    };

    Some(ret)
}

// https://tools.ietf.org/html/rfc5285
fn parse_bede<'a>(mut buf: &'a [u8], ext: &mut RtpExtValues<'a>, id_to_ext: &IdToExtType) {
    loop {
        if buf.is_empty() {
            return;
        }

        if buf[0] == 0 {
            // padding
            buf = &buf[1..];
            continue;
        }

        let id = buf[0] >> 4;
        let len = (buf[0] & 0xf) as usize + 1;
        buf = &buf[1..];

        if id == 15 {
            // If the ID value 15 is
            // encountered, its length field should be ignored, processing of the
            // entire extension should terminate at that point, and only the
            // extension elements present prior to the element with ID 15
            // considered.
            return;
        }

        if buf.len() < len {
            trace!("Not enough type ext len: {} < {}", buf.len(), len);
            return;
        }

        let typ_buf = &buf[..len];
        let typ = id_to_ext.lookup(id);

        typ.parse_value(typ_buf, ext);

        buf = &buf[len..];
    }
}

/// Mapping between RTP extension id to what extension that is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdToExtType([RtpExtensionType; 14]);

impl IdToExtType {
    pub fn new() -> Self {
        IdToExtType([RtpExtensionType::UnknownExt; 14])
    }

    pub fn apply_ext_map(&mut self, v: &[ExtMap]) -> Result<(), Error> {
        for x in v {
            if x.id >= 1 && x.id <= 14 {
                // Mapping goes from 0 to 13.
                let id = x.id as usize - 1;

                if self.0[id] == RtpExtensionType::UnknownExt {
                    self.0[id] = x.ext_type;
                } else if self.0[id] == x.ext_type {
                    // Same type
                } else {
                    // We assume that an ext-type mapping cannot be different within the context
                    // of one RTP session. If they are different, we have no strategy for parsing
                    // the mid from a RTP packet to match it up with an m-line (avoiding a=ssrc).
                    // If we see this error, we must make fallback strategies for how to match
                    // incoming RTP to a Media/IngressStream.
                    return Err(err!(
                        ErrorKind::SdpApply,
                        "Differing ext id to ext type: {:?} != {:?}",
                        self.0[id],
                        x.ext_type
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn lookup(&self, id: u8) -> RtpExtensionType {
        if id >= 1 && id <= 14 {
            self.0[id as usize - 1]
        } else {
            debug!("Lookup RTP extension out of range 1-14: {}", id);
            RtpExtensionType::UnknownExt
        }
    }
}

impl RtpExtensionType {
    fn parse_value<'a>(&self, buf: &'a [u8], v: &mut RtpExtValues<'a>) -> Option<()> {
        match self {
            // 3
            RtpExtensionType::AbsoluteSendTime => {
                // fixed point 6.18
                let time_24 = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
                let time_fp = time_24 as f32 / (2 ^ 18) as f32;
                v.abs_send_time = Some(Ts::from_seconds(time_fp as f64));
            }
            // 1
            RtpExtensionType::AudioLevel => {
                v.audio_level = Some(-(0x7f & buf[0] as i8));
                v.voice_activity = Some(buf[0] & 0x80 > 0);
            }
            // 3
            RtpExtensionType::TransmissionTimeOffset => {
                v.tx_time_offs = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            // 1
            RtpExtensionType::VideoOrientation => {
                v.video_orient = Some(buf[0] & 3);
            }
            // 2
            RtpExtensionType::TransportSequenceNumber => {
                v.transport_cc = Some(u32::from_be_bytes([0, 0, buf[0], buf[1]]));
            }
            // 3
            RtpExtensionType::PlayoutDelay => {
                let min = (buf[0] as u32) << 4 | (buf[1] as u32) >> 4;
                let max = (buf[1] as u32) << 8 | buf[2] as u32;
                v.play_delay_min = Some(Ts::new(min as f64, 100.0));
                v.play_delay_max = Some(Ts::new(max as f64, 100.0));
            }
            // 1
            RtpExtensionType::VideoContentType => {
                v.video_c_type = Some(buf[0]);
            }
            // 13
            RtpExtensionType::VideoTiming => {
                v.video_timing = Some(VideoTiming {
                    flags: buf[0],
                    encode_start: u32::from_be_bytes([0, 0, buf[1], buf[2]]),
                    encode_finish: u32::from_be_bytes([0, 0, buf[2], buf[3]]),
                    packetize_complete: u32::from_be_bytes([0, 0, buf[4], buf[5]]),
                    last_left_pacer: u32::from_be_bytes([0, 0, buf[6], buf[7]]),
                    //  8 -  9 // reserved for network
                    // 10 - 11 // reserved for network
                })
            }
            RtpExtensionType::RtpStreamId => {
                let s = from_utf8(buf).ok()?;
                v.stream_id = Some(s);
            }
            RtpExtensionType::RepairedRtpStreamId => {
                let s = from_utf8(buf).ok()?;
                v.rep_stream_id = Some(s);
            }
            RtpExtensionType::RtpMid => {
                let s = from_utf8(buf).ok()?;
                v.rtp_mid = Some(s);
            }
            RtpExtensionType::FrameMarking => {
                v.frame_mark = Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
            }
            RtpExtensionType::ColorSpace => {
                // TODO HDR color space
            }
            RtpExtensionType::UnknownUri | RtpExtensionType::UnknownExt => {
                // ignore
            }
        }

        Some(())
    }
}

#[derive(Clone, Default)]
pub struct RtpExtValues<'a> {
    pub abs_send_time: Option<Ts>,
    pub voice_activity: Option<bool>,
    pub audio_level: Option<i8>,
    pub tx_time_offs: Option<u32>,
    pub video_orient: Option<u8>,  // TODO map out values buf[0] & 3;
    pub transport_cc: Option<u32>, // (buf[0] << 8) | buf[1];
    // https://webrtc.googlesource.com/src/+/refs/heads/master/docs/native-code/rtp-hdrext/playout-delay
    pub play_delay_min: Option<Ts>,
    pub play_delay_max: Option<Ts>,
    pub video_c_type: Option<u8>, // 0 = unspecified, 1 = screenshare
    pub video_timing: Option<VideoTiming>,
    pub stream_id: Option<&'a str>,
    pub rep_stream_id: Option<&'a str>,
    pub rtp_mid: Option<&'a str>,
    pub frame_mark: Option<u32>,
}

impl<'a> fmt::Debug for RtpExtValues<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RtpExtValues {{")?;

        if let Some(t) = self.rtp_mid {
            write!(f, " mid: {}", t)?;
        }
        if let Some(t) = self.stream_id {
            write!(f, " stream_id: {}", t)?;
        }
        if let Some(t) = self.rep_stream_id {
            write!(f, " rep_stream_id: {}", t)?;
        }
        if let Some(t) = self.abs_send_time {
            write!(f, " abs_send_time: {}", t.to_seconds())?;
        }
        if let Some(t) = self.voice_activity {
            write!(f, " voice_activity: {}", t)?;
        }
        if let Some(t) = self.audio_level {
            write!(f, " audio_level: {}", t)?;
        }
        if let Some(t) = self.tx_time_offs {
            write!(f, " tx_time_offs: {}", t)?;
        }
        if let Some(t) = self.video_orient {
            write!(f, " video_orient: {}", t)?;
        }
        if let Some(_) = self.transport_cc {
            write!(f, " transport_cc: TODO")?;
        }
        if let Some(t) = self.play_delay_min {
            write!(f, " play_delay_min: {}", t.to_seconds())?;
        }
        if let Some(t) = self.play_delay_max {
            write!(f, " play_delay_max: {}", t.to_seconds())?;
        }
        if let Some(t) = self.video_c_type {
            write!(f, " video_c_type: {}", t)?;
        }
        if let Some(t) = &self.video_timing {
            write!(f, " video_timing: {:?}", t)?;
        }
        if let Some(_) = &self.frame_mark {
            write!(f, " frame_mark: TODO")?;
        }

        write!(f, " }}")?;
        Ok(())
    }
}

impl<'a> RtpExtValues<'a> {
    //
}

#[derive(Debug, Clone)]
pub struct VideoTiming {
    // 0x01 = extension is set due to timer.
    // 0x02 - extension is set because the frame is larger than usual.
    flags: u8,
    encode_start: u32,
    encode_finish: u32,
    packetize_complete: u32,
    last_left_pacer: u32,
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

/// Determine number of packets expected and lost.
impl IngressStream {
    pub fn determine_loss(&mut self) {
        // https://tools.ietf.org/html/rfc3550#appendix-A.3
        let expected = (self.rtp_max_seq - self.rtp_start_seq + 1) as i64;
        let received = self.rtp_packet_count as i64;
        let lost = expected - received;

        let mut fract = 0;

        if self.rtp_packets_expected_prior != 0 && self.rtp_packets_received_prior != 0 {
            let expected_interval = self.rtp_packets_expected_prior - expected;
            let received_interval = self.rtp_packets_received_prior - received;

            let lost_interval = expected_interval - received_interval;

            if expected_interval == 0 || lost_interval <= 0 {
                fract = 0;
            } else {
                fract = (lost_interval << 8) / expected_interval;
            }
        }

        self.rtp_packets_expected_prior = expected;
        self.rtp_packets_received_prior = received;
        self.rtp_lost_packets = lost;
        self.rtp_packet_loss = fract as f32 / 255.0;
    }

    pub fn estimate_jitter(&mut self, sys_time: Ts, rtp_time: Ts) {
        // https://tools.ietf.org/html/rfc3550#appendix-A.8
        let rtp_timebase = rtp_time.denum();

        if !self.rtp_sys_time_prior.is_zero() {
            let transit = sys_time - rtp_time;
            let transit_prior = self.rtp_sys_time_prior - self.rtp_time_prior;
            let d = (transit - transit_prior).abs().rebase(rtp_timebase);

            self.rtp_jitter += 1.0 / 16.0 * (d.numer() - self.rtp_jitter);
            self.rtp_jitter_norm = self.rtp_jitter / rtp_timebase;
        }

        self.rtp_sys_time_prior = sys_time;
        self.rtp_time_prior = rtp_time;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_estimate_srtp_index() {
        assert_eq!(extend_seq(None, 0), 0);
        assert_eq!(extend_seq(Some(0), 1), 1);
        assert_eq!(extend_seq(Some(65_535), 0), 65_536);
        assert_eq!(extend_seq(Some(65_500), 2), 65_538);
        assert_eq!(extend_seq(Some(2), 1), 1);
        assert_eq!(extend_seq(Some(65_538), 1), 65_537);
    }
}
