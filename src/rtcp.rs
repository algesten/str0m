use crate::media::IngressStream;
use crate::peer::Peer;
use crate::peer::PeerUdp;
use crate::util::Ts;

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

pub fn parse_header(buf: &[u8], is_srtcp: bool) -> Option<RtcpHeader> {
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
    //
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
        trace!("SRTCP packet requires SenderReport or ReceiverReport");
        return None;
    }

    let length_be = [buf[2], buf[3]];

    // https://tools.ietf.org/html/rfc3550#section-6.4.1
    //   The length of this RTCP packet in 32-bit words minus one,
    //   including the header and any padding. (The offset of one makes
    //   zero a valid length ...)
    let length = (u16::from_be_bytes(length_be) + 1) * 4;

    return Some(RtcpHeader {
        version,
        has_padding,
        fmt,
        packet_type,
        length: length as usize,
    });
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

pub fn handle_sender_report(udp: &PeerUdp, peer: &mut Peer, buf: &[u8]) -> Option<()> {
    if buf.len() < 20 {
        return None;
    }

    // Sender report shape is here
    // https://tools.ietf.org/html/rfc3550#page-36
    let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    let media = peer.media_by_ingress_ssrc(ssrc)?;

    let stream = media.ingress_by_ssrc(ssrc)?;
    let ntp_time = u64::from_be_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    let rtp_time = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

    stream.rtcp_sr_last = udp.timestamp;
    stream.rtcp_sr_ntp = Ts::from_micros(ntp_time as f64);

    // https://www.cs.columbia.edu/~hgs/rtp/faq.html#timestamp-computed
    // For video, time clock rate is fixed at 90 kHz. The timestamps generated
    // depend on whether the application can determine the frame number or not.
    // If it can or it can be sure that it is transmitting every frame with a
    // fixed frame rate, the timestamp is governed by the nominal frame rate.
    // Thus, for a 30 f/s video, timestamps would increase by 3,000 for each
    // frame, for a 25 f/s video by 3,600 for each frame.
    stream.rtcp_sr_rtp = rtp_time;

    Some(())
}

impl IngressStream {
    pub fn build_receiver_report(&mut self, buf: &mut [u8]) -> Option<()> {
        assert!(buf.len() == 24);

        // This rebuilds the packet loss fields.
        self.determine_loss();

        (&mut buf[0..4]).copy_from_slice(&self.ssrc.to_be_bytes());
        buf[4] = (self.rtp_packet_loss * 255.0) as u8;
        (&mut buf[5..8]).copy_from_slice(&self.rtp_lost_packets.to_be_bytes()[5..]);
        (&mut buf[8..12]).copy_from_slice(&self.rtp_ext_seq?.to_be_bytes()[4..]);

        Some(())
    }
}
