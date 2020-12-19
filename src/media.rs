use std::net::SocketAddr;

use crate::format::Format;
use crate::peer::IceCreds;
use crate::sdp::*;
use crate::util::Ts;
use crate::util::VecExt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupId(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Audio,
    Video,
    Application,
}

/// Media direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    SendOnly,
    RecvOnly,
    SendRecv,
    Inactive,
}

impl Direction {
    pub fn is_recv(&self) -> bool {
        match self {
            Direction::RecvOnly | Direction::SendRecv => true,
            _ => false,
        }
    }
}

/// `Media` is one single thing, like a user mic, or a screen grab or a camera.
///
/// It corresponds to one m-line in the SDP, however it can be bi-directional when
/// using unified plan thus having both ingress and egress.
#[derive(Debug)]
pub struct Media {
    /// Identifier unique within the scope of the PeerId. This is the "mid" from
    /// `a=mid:<value>`.
    pub media_id: MediaId,

    /// Direction as per a=sendonly, a=sendrecv, a=recvonly, a=inactive.
    pub direction: Direction,

    /// Audio, Video or Application (for data channels).
    pub kind: MediaKind,

    /// Media formats. This will contain at least one "main" format such as h264 or opus, but also
    /// all related repair stream formats.
    pub formats: Vec<Format>,

    /// Further restrictions on the formats (a=rid)
    pub restrictions: Vec<Restriction>,

    /// Simulcast groupings (a=simulcast)
    pub simulcast: Option<Simulcast>,

    /// Ice username/password. From a=ice-ufrag/a=ice-pwd.
    pub ice_creds: IceCreds,

    /// Fingerprint from a=fingerprint.
    pub fingerprint: Fingerprint,

    /// Extensions
    pub extmaps: Vec<ExtMap>,

    /// Ingress or egress streams depending on direction of media.
    pub ingress: Vec<IngressStream>,
    pub egress: Vec<EgressStream>,
}

#[derive(Debug)]
pub struct IngressStream {
    pub ssrc: u32,

    /// Address this ingress originates from.
    pub addr: SocketAddr,

    /// If this ingress is a repair stream, this is the SSRC of the stream it repairs.
    pub repaired_ssrc: Option<u32>,

    /// Groups `IngressStream` that belongs together. Like audio and video from the same source.
    /// All media in the group goes in the same direction and are to be synchronized at
    /// when playing.
    ///
    /// According to spec these should be using an `a=group:LS` property, but that
    /// doesn't exist in practice. We set the group id using the SDES CNAME.
    pub group_id: Option<GroupId>,

    /// Optional SDES (RTCP source description) stream id sent as RTP bede header.
    /// In SDP this feature is called
    /// "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"
    /// We only set this first time we "discover" what it is in the RTP.
    pub stream_id: Option<StreamId>,

    /// Last (extended) RTP packet sequence number.
    pub rtp_ext_seq: Option<u64>,

    /// Number of rtp packets received.
    pub rtp_packet_count: u64,
    /// First sequence number of rtp packets.
    pub rtp_start_seq: u64,
    /// Max seen rtp packet sequence number.
    pub rtp_max_seq: u64,
    /// Number of (unprotected) RTP bytes received.
    pub rtp_bytes: u64,

    /// Last expected packets, saved for each determine_loss().
    pub rtp_packets_expected_prior: i64,
    /// Last received packets, saved for each determine_loss().
    pub rtp_packets_received_prior: i64,

    /// Absolute number of lost packets found in last determine_loss().
    pub rtp_lost_packets: i64,
    /// Packet loss found in last determine_loss().
    pub rtp_packet_loss: f32,

    /// Last system time saved in estimate_jitter().
    pub rtp_sys_time_prior: Ts,
    /// Last RTP time saved in estimate_jitter().
    pub rtp_time_prior: Ts,

    /// Jitter as calculated by estimate_jitter() in the timebase of the codec.
    pub rtp_jitter: f64,
    /// Normalized jitter (in seconds).
    pub rtp_jitter_norm: f64,

    /// Last system time we received a sender report.
    pub rtcp_sr_last: Ts,
    /// Last sender report ntp time.
    pub rtcp_sr_ntp: Ts,
    /// Last sender report rtp time.
    pub rtcp_sr_rtp: u32,
}

#[derive(Debug)]
pub struct EgressStream {
    pub ssrc: u32,
}

impl Media {
    pub fn new(media_id: MediaId) -> Self {
        Media {
            media_id,
            direction: Direction::Inactive,
            kind: MediaKind::Audio,
            formats: vec![],
            restrictions: vec![],
            simulcast: None,
            ice_creds: IceCreds {
                username: "".to_string(),
                password: "".to_string(),
            },
            fingerprint: Fingerprint {
                hash_func: "".to_string(),
                bytes: vec![],
            },
            extmaps: vec![],
            ingress: vec![],
            egress: vec![],
        }
    }

    /// Whether an ingress SSRC is associated with this Media.
    pub fn has_ingress_ssrc(&self, ssrc: u32) -> bool {
        self.ingress.iter().any(|i| i.ssrc == ssrc)
    }

    pub fn ingress_create_ssrc(&mut self, ssrc: u32, addr: &SocketAddr) -> &mut IngressStream {
        self.ingress
            .find_or_append(|i| i.ssrc == ssrc, || IngressStream::new(ssrc, *addr))
    }

    pub fn ingress_by_ssrc(&mut self, ssrc: u32) -> Option<&mut IngressStream> {
        self.ingress.iter_mut().find(|i| i.ssrc == ssrc)
    }

    pub fn ingress_by_stream_id(&mut self, stream_id: &str) -> Option<&mut IngressStream> {
        self.ingress
            .iter_mut()
            .find(|i| i.stream_id_str() == Some(stream_id))
    }

    pub fn format_for_ingress(&self, stream: &IngressStream) -> Option<&Format> {
        if let Some(ssrc) = stream.repaired_ssrc {
            // Figure out Format for the stream this is repairing.
            let repaired_format = self.format_for_ssrc(ssrc)?;

            // Find format that points to the repaired format.
            self.formats
                .iter()
                .find(|f| f.is_repair() && f.fmtp_apt() == Some(repaired_format.map_no))
        } else {
            if let Some(stream_id) = &stream.stream_id {
                self.formats
                    .iter()
                    .find(|f| f.restrictions.contains(stream_id))
            } else {
                // Fallback if there are no stream_id
                self.formats.get(0)
            }
        }
    }

    fn format_for_ssrc(&self, ssrc: u32) -> Option<&Format> {
        let stream = self.ingress.iter().find(|i| i.ssrc == ssrc)?;
        self.format_for_ingress(stream)
    }

    pub fn active_ingress<'a>(&'a mut self, into: &mut Vec<&'a mut IngressStream>) {
        if !self.direction.is_recv() {
            return;
        }

        for stream in &mut self.ingress {
            if stream.rtp_ext_seq.is_some() {
                into.push(stream);
            }
        }
    }
}

impl IngressStream {
    pub fn new(ssrc: u32, addr: SocketAddr) -> Self {
        IngressStream {
            ssrc,

            addr,

            repaired_ssrc: None,

            group_id: None,

            stream_id: None,

            rtp_ext_seq: None,
            rtp_packet_count: 0,
            rtp_start_seq: 0,
            rtp_max_seq: 0,
            rtp_bytes: 0,

            rtp_packets_expected_prior: 0,
            rtp_packets_received_prior: 0,

            rtp_lost_packets: 0,
            rtp_packet_loss: 0.0,

            rtp_sys_time_prior: Ts::ZERO,
            rtp_time_prior: Ts::ZERO,

            rtp_jitter: 0.0,
            rtp_jitter_norm: 0.0,

            rtcp_sr_last: Ts::ZERO,
            rtcp_sr_ntp: Ts::ZERO,
            rtcp_sr_rtp: 0,
        }
    }

    fn stream_id_str(&self) -> Option<&str> {
        self.stream_id.as_ref().map(|s| s.0.as_str())
    }
}

trait MediaThings {
    fn for_mid(&self, mid: &MediaId) -> Option<&Media>;
}

impl MediaThings for Vec<Media> {
    fn for_mid(&self, mid: &MediaId) -> Option<&Media> {
        self.iter().find(|m| &m.media_id == mid)
    }
}

impl Direction {
    pub fn flip(self) -> Self {
        use Direction::*;
        match self {
            SendOnly => RecvOnly,
            RecvOnly => SendOnly,
            SendRecv => SendRecv,
            Inactive => Inactive,
        }
    }
}
