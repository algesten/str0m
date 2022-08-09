use std::str::from_utf8;

use crate::MediaTime;

/// Header size before receiver report blocks.
pub const RR_HEAD: usize = 8;
/// Size of one receiver report.
pub const RR_LEN: usize = 24;
/// Max number of receiver reports per RTCP packet.
pub const RR_MAX: usize = 32;

#[derive(Debug)]
pub struct RtcpHeader {
    pub version: u8,
    pub has_padding: bool,
    pub fmt: Fmt,
    pub packet_type: PacketType,
    pub length: usize,
}

/// Number of _something_ in the RTCP packet.
///
/// PacketType determines how to interpret the count field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fmt {
    /// When packet type SenderReport or ReceiverReport
    ReceptionReport(u8),
    /// When packet type SourceDescription or Goodbye
    SourceCount(u8),
    /// When packet type ApplicationDefined
    Subtype(u8),
    /// When packet type is TransportLayerFeedback
    TransportFeedback(TransportType),
    /// When packet type is PayloadSpecificFeedback
    PayloadFeedback(PayloadType),
    /// When the packet type is ExtendedReport
    NotUsed,
}

impl Fmt {
    pub fn count(&self) -> u8 {
        match self {
            Fmt::ReceptionReport(v) => *v,
            Fmt::SourceCount(v) => *v,
            _ => panic!("Not a count"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Nack = 1,
    // https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01
    TransportWide = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    PictureLossIndication = 1, // PLI
    SliceLossIndication = 2,
    ReferencePictureSelectionIndication = 3,
    FullIntraRequest = 4, // FIR
    ApplicationLayer = 15,
}

/// Kind of RTCP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// RTCP_PT_SR
    SenderReport = 200,
    /// RTCP_PT_RR
    ReceiverReport = 201,
    /// RTCP_PT_SDES
    SourceDescription = 202,
    /// RTCP_PT_BYE
    Goodbye = 203,

    /// RTCP_PT_APP
    ApplicationDefined = 204,
    /// RTCP_PT_RTPFB
    // https://tools.ietf.org/html/rfc4585
    TransportLayerFeedback = 205,
    /// RTCP_PT_PSFB
    // https://tools.ietf.org/html/rfc4585
    PayloadSpecificFeedback = 206,
    /// RTCP_PT_XR
    ExtendedReport = 207,
}

impl RtcpHeader {
    pub fn parse(buf: &[u8], is_srtcp: bool) -> Option<RtcpHeader> {
        use PacketType::*;

        if buf.len() < 8 {
            trace!("RTCP header too short < 8: {}", buf.len());
            return None;
        }

        let version = (buf[0] & 0b1100_0000_u8) >> 6;
        if version != 2 {
            trace!("RTCP version is not 2");
            return None;
        }
        let has_padding = buf[0] & 0b0010_0000 > 0;

        let fmt_n = buf[0] & 0b0001_1111;
        let packet_type = PacketType::from_u8(buf[1])?;
        let fmt = match packet_type {
            SenderReport | ReceiverReport => Fmt::ReceptionReport(fmt_n),
            SourceDescription | Goodbye => Fmt::SourceCount(fmt_n),
            ApplicationDefined => Fmt::Subtype(fmt_n),
            TransportLayerFeedback => Fmt::TransportFeedback(TransportType::from_u8(fmt_n)?),
            PayloadSpecificFeedback => Fmt::PayloadFeedback(PayloadType::from_u8(fmt_n)?),
            ExtendedReport => Fmt::NotUsed,
        };

        if is_srtcp && packet_type != SenderReport && packet_type != ReceiverReport {
            // The first RTCP packet in the compound packet MUST
            // always be a report packet to facilitate header validation as
            // described in Appendix A.2.  This is true even if no data has been
            // sent or received, in which case an empty RR MUST be sent, and even
            // if the only other RTCP packet in the compound packet is a BYE.
            trace!("SRTCP packet requires SenderReport or ReceiverReport");
            return None;
        }

        let length_be = [buf[2], buf[3]];

        // https://tools.ietf.org/html/rfc3550#section-6.4.1
        //   The length of this RTCP packet in 32-bit words minus one,
        //   including the header and any padding. (The offset of one makes
        //   zero a valid length ...)
        let length = (u16::from_be_bytes(length_be) + 1) * 4;

        Some(RtcpHeader {
            version,
            has_padding,
            fmt,
            packet_type,
            length: length as usize,
        })
    }
}

impl TransportType {
    fn from_u8(v: u8) -> Option<Self> {
        use TransportType::*;
        match v {
            1 => Some(Nack),
            15 => Some(TransportWide),
            _ => {
                trace!("Unrecognized TransportSpecificFeedback type: {}", v);
                None
            }
        }
    }
}

impl PayloadType {
    fn from_u8(v: u8) -> Option<PayloadType> {
        use PayloadType::*;
        match v {
            1 => Some(PictureLossIndication),
            2 => Some(SliceLossIndication),
            3 => Some(ReferencePictureSelectionIndication),
            4 => Some(FullIntraRequest),
            15 => Some(ApplicationLayer),
            _ => {
                trace!("Unrecognized PayloadSpecificFeedback type: {}", v);
                None
            }
        }
    }
}

impl PacketType {
    fn from_u8(v: u8) -> Option<Self> {
        use PacketType::*;
        match v {
            200 => Some(SenderReport),   // sr
            201 => Some(ReceiverReport), // rr
            202 => Some(SourceDescription),
            203 => Some(Goodbye),
            204 => Some(ApplicationDefined),
            205 => Some(TransportLayerFeedback),
            206 => Some(PayloadSpecificFeedback),
            207 => Some(ExtendedReport),
            _ => {
                trace!("Unrecognized RTCP type: {}", v);
                None
            }
        }
    }
}

pub fn handle_sender_report(header: &RtcpHeader, buf: &[u8]) -> Option<()> {
    // Sender report shape is here
    // https://tools.ietf.org/html/rfc3550#page-36
    if buf.len() < 20 {
        return None;
    }

    let mut buf = &buf[4..];

    let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    // let media = match peer.media_by_ingress_ssrc(ssrc) {
    //     Some(v) => v,
    //     None => {
    //         trace!("Send report no ingress for SSRC: {}", ssrc);
    //         return None;
    //     }
    // };

    // let stream = media.ingress_by_ssrc(ssrc)?;

    let ntp_time = u64::from_be_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    let rtp_time = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

    // stream.rtcp_sr_last = udp.timestamp;
    // stream.rtcp_sr_ntp = MediaTime::from_ntp_64(ntp_time);

    // https://www.cs.columbia.edu/~hgs/rtp/faq.html#timestamp-computed
    // For video, time clock rate is fixed at 90 kHz. The timestamps generated
    // depend on whether the application can determine the frame number or not.
    // If it can or it can be sure that it is transmitting every frame with a
    // fixed frame rate, the timestamp is governed by the nominal frame rate.
    // Thus, for a 30 f/s video, timestamps would increase by 3,000 for each
    // frame, for a 25 f/s video by 3,600 for each frame.
    // stream.rtcp_sr_rtp = rtp_time;

    // Number of sender reports.
    // For WebRTC this seems to always be 0?
    let count = header.fmt.count();

    for _ in 0..count {
        buf = &buf[24..]; // by chance the sender info is same size as a report block.
        handle_sender_report_block(buf)?;
    }

    Some(())
}

// Seems unused for WebRTC.
fn handle_sender_report_block(buf: &[u8]) -> Option<()> {
    let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    trace!("TODO sender report block: {}", ssrc);
    Some(())
}

pub fn receiver_report_header(buf: &mut [u8]) {
    assert!(buf.len() >= RR_HEAD + RR_LEN);

    let buf_len = buf.len();

    let report_count = (buf_len - RR_HEAD) / RR_LEN;
    buf[0] = (2 << 6) | (report_count as u8);
    buf[1] = 200;

    (&mut buf[2..4]).copy_from_slice(&(buf_len as u16).to_be_bytes());

    // SSRC of sender. But we don't really have an SSRC, so this is some workaround.
    let first_ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    (&mut buf[4..8]).copy_from_slice(&(first_ssrc + 1_u32).to_be_bytes());
}

// impl IngressStream {
//     pub fn build_receiver_report(&mut self, buf: &mut [u8], systime: MediaTime) {
//         assert!(buf.len() == 24);

//         // This rebuilds the packet loss fields.
//         self.determine_loss();

//         (&mut buf[0..4]).copy_from_slice(&self.ssrc.to_be_bytes());
//         buf[4] = (self.rtp_packet_loss * 255.0) as u8;
//         (&mut buf[5..8]).copy_from_slice(&self.rtp_lost_packets.to_be_bytes()[5..]);
//         (&mut buf[8..12]).copy_from_slice(&self.rtp_ext_seq.unwrap().to_be_bytes()[4..]);

//         (&mut buf[12..16]).copy_from_slice(&(self.rtp_jitter as u32).to_be_bytes());

//         // https://tools.ietf.org/html/rfc3550#section-6.4
//         // The middle 32 bits out of 64 in the NTP timestamp (as explained in
//         // Section 4) received as part of the most recent RTCP sender report
//         // (SR) packet from source SSRC_n.  If no SR has been received yet,
//         // the field is set to zero.
//         let last_sr = self.rtcp_sr_last.as_ntp_32();
//         (&mut buf[16..20]).copy_from_slice(&last_sr.to_be_bytes());

//         // The delay, expressed in units of 1/65536 seconds, between
//         // receiving the last SR packet from source SSRC_n and sending this
//         // reception report block.  If no SR packet has been received yet
//         // from SSRC_n, the DLSR field is set to zero.
//         let delay_last_sr = if self.rtcp_sr_last.is_zero() {
//             0
//         } else {
//             (((systime - self.rtcp_sr_last).as_micros()) * 65_536 / 1_000_000) as u32
//         };
//         (&mut buf[20..24]).copy_from_slice(&delay_last_sr.to_be_bytes());
//     }
// }

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SdesType {
    /// End of SDES list
    END = 0,
    /// Canonical name.
    CNAME = 1,
    /// User name
    NAME = 2,
    /// User's electronic mail address
    EMAIL = 3,
    /// User's phone number
    PHONE = 4,
    /// Geographic user location
    LOC = 5,
    /// Name of application or tool
    TOOL = 6,
    /// Notice about the source
    NOTE = 7,
    /// Private extensions
    PRIV = 8,
    /// Who knows
    Unknown,
}

pub fn handle_source_description(header: &RtcpHeader, buf: &[u8]) -> Option<()> {
    // https://tools.ietf.org/html/rfc3550#page-45

    // Number of source descriptions (SDES)
    let count = header.fmt.count();

    // position to read next sdes buf from.
    let mut buf = &buf[4..];
    for _ in 0..count {
        let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

        let sdes_type = SdesType::from_u8(buf[4]);
        let sdes_len = buf[5] as usize;
        let text = from_utf8(&buf[6..(6 + sdes_len)]).ok()?;

        if sdes_type == SdesType::CNAME {
            // if let Some(media) = peer.media_by_ingress_ssrc(ssrc) {
            //     if let Some(ingress) = media.ingress_by_ssrc(ssrc) {
            //         if ingress.group_id.is_none() {
            //             debug!("Associate SSRC {} with CNAME: {}", ssrc, text);
            //             ingress.group_id = Some(GroupId(text.to_string()));
            //         }
            //     }
            // }
        } else {
            trace!("Unused SDES {:?}={}", sdes_type, text);
        }

        buf = &buf[(6 + sdes_len)..];
    }

    None
}

impl SdesType {
    fn from_u8(u: u8) -> Self {
        use SdesType::*;
        match u {
            0 => END,
            1 => CNAME,
            2 => NAME,
            3 => EMAIL,
            4 => PHONE,
            5 => LOC,
            6 => TOOL,
            7 => NOTE,
            8 => PRIV,
            _ => Unknown,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// Record of receiving one transport wide cc.
pub struct TransportWideCC(pub u16, pub MediaTime);

pub const TRANSPORT_WIDE_CC_MAX: usize = 4;

pub fn build_transport_fb(
    send_transport_cc: &mut u8,
    ssrc: u32,
    timestamp: &MediaTime,
    to_send: &mut [Option<TransportWideCC>],
    output: &mut Vec<Vec<u8>>,
) -> Option<()> {
    // https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01

    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |V=2|P|  FMT=15 |    PT=205     |           length              |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                     SSRC of packet sender                     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      SSRC of media source                     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |      base sequence number     |      packet status count      |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                 reference time                | fb pkt. count |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          packet chunk         |         packet chunk          |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    .                                                               .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |         packet chunk          |  recv delta   |  recv delta   |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    .                                                               .
    //    .                                                               .
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |           recv delta          |  recv delta   | zero padding  |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Deltas are represented as multiples of 250us:
    // o  If the "Packet received, small delta" symbol has been appended to
    //     the status list, an 8-bit unsigned receive delta will be appended
    //     to recv delta list, representing a delta in the range [0, 63.75]
    //     ms.
    // o  If the "Packet received, large or negative delta" symbol has been
    //     appended to the status list, a 16-bit signed receive delta will be
    //     appended to recv delta list, representing a delta in the range
    //     [-8192.0, 8191.75] ms.
    const DELTA: i64 = 250; // microseconds
    const WRAP_PERIOD: i64 = 1 << 24;

    loop {
        // If no index found, deliberate early return
        let mut index = to_send.iter().position(|t| t.is_none())?;
        let first = to_send[index].take()?;

        let buf = vec![0_u8; 256];
        output.push(buf);
        let last = output.len() - 1;

        let buf = output.get_mut(last).unwrap();
        buf.resize(20, 0); // space for header + 1 chunk.

        // 5 bits This field identifies the type
        // of the FB message.  It must have the value 15.
        buf[0] = 2 << 6 | 15;
        // 8 bits This is the RTCP packet type that
        // identifies the packet as being an RTCP FB message.  The
        // value must be RTPFB = 205.
        buf[1] = PacketType::TransportLayerFeedback as u8;
        // len and padding written afterwards

        buf[4..8].copy_from_slice(&ssrc.to_be_bytes());
        buf[8..12].copy_from_slice(&(ssrc + 1).to_be_bytes());

        let base_seq = first.0;
        buf[12..14].copy_from_slice(&base_seq.to_be_bytes());
        let mut total_count = 0;
        // packet status count written after

        let ref_time = first.1;
        let fb_count = *send_transport_cc;
        *send_transport_cc += 1;

        let t_and_c = (((ref_time.as_micros() % WRAP_PERIOD) / DELTA) << 8) | (fb_count as i64);
        buf[16..20].copy_from_slice(&t_and_c.to_be_bytes());

        let mut cur = first;
        let mut deltas = Vec::with_capacity(TRANSPORT_WIDE_CC_MAX);
        let mut chunks = 0;

        loop {
            let delta_ts = cur.1 - ref_time;
            deltas.push(delta_ts);

            let delta = delta_ts.as_micros() / DELTA;

            if delta < -32768 || delta > 32767 {
                // If the delta exceeds even the larger limits, a new feedback
                // message must be used, where the 24-bit base receive delta can
                // cover very large gaps.
                break;
            }

            // Position for handling next one.
            index += 1;
            if index == to_send.len() {
                break;
            }
            cur = to_send[index].take().unwrap();
        }

        // write deltas
        // write status count, len and padding
    }

    Some(())
}
