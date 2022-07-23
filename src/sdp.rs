use std::fmt;
use std::net::IpAddr;
use std::num::ParseFloatError;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sdp {
    pub session: Session,
    pub transceivers: Vec<TransceiverInfo>,
}

/// Credentials for STUN packages.
///
/// By matching IceCreds in STUN to SDP, we know which STUN belongs to which Peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IceCreds {
    // From a=ice-ufrag
    pub username: String,
    // From a=ice-pwd
    pub password: String,
}

pub trait MediaAttributeExt {
    fn extmaps(&self) -> Vec<ExtMap>;
    fn ssrc_info(&self) -> Vec<SsrcInfo>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrcInfo {
    pub ssrc: u32,
    pub cname: String,
    // If this is a repair stream, this is the SSRC it repairs. This is
    // figured out using a=ssrc-group:FID <main> <repair>
    pub repaired_ssrc: Option<u32>,
}

impl MediaAttributeExt for Vec<MediaAttribute> {
    fn extmaps(&self) -> Vec<ExtMap> {
        let mut ret = vec![];

        for a in self {
            if let MediaAttribute::ExtMap(e) = a {
                ret.push(e.clone());
            }
        }

        ret
    }

    fn ssrc_info(&self) -> Vec<SsrcInfo> {
        let mut ret = vec![];

        let mut fids = vec![];

        for a in self {
            if let MediaAttribute::SsrcGroup { semantics, ssrcs } = a {
                if semantics != "FID" {
                    continue;
                }
                if ssrcs.len() != 2 {
                    trace!("Found a=ssrc-group=FID without two SSRC: {:?}", ssrcs);
                    continue;
                }
                fids.push((ssrcs[0], ssrcs[1]));
            }
        }

        for a in self {
            if let MediaAttribute::Ssrc { ssrc, attr, value } = a {
                let repaired_ssrc = fids
                    .iter()
                    .find(|(_, rtx)| rtx == ssrc)
                    .map(|(main, _)| *main);

                if attr == "cname" {
                    ret.push(SsrcInfo {
                        ssrc: *ssrc,
                        cname: value.clone(),
                        repaired_ssrc,
                    });
                }
            }
        }

        ret
    }
}

pub trait IceExt {
    fn username(&self) -> Option<&str>;
    fn password(&self) -> Option<&str>;
    fn fingerprint(&self) -> Option<&Fingerprint>;
}

impl IceExt for Vec<MediaAttribute> {
    fn username(&self) -> Option<&str> {
        for a in self {
            if let MediaAttribute::IceUfrag(v) = a {
                return Some(v);
            }
        }
        None
    }
    fn password(&self) -> Option<&str> {
        for a in self {
            if let MediaAttribute::IcePwd(v) = a {
                return Some(v);
            }
        }
        None
    }
    fn fingerprint(&self) -> Option<&Fingerprint> {
        for a in self {
            if let MediaAttribute::Fingerprint(v) = a {
                return Some(v);
            }
        }
        None
    }
}

impl IceExt for Vec<SessionAttribute> {
    fn username(&self) -> Option<&str> {
        for a in self {
            if let SessionAttribute::IceUfrag(v) = a {
                return Some(v);
            }
        }
        None
    }
    fn password(&self) -> Option<&str> {
        for a in self {
            if let SessionAttribute::IcePwd(v) = a {
                return Some(v);
            }
        }
        None
    }
    fn fingerprint(&self) -> Option<&Fingerprint> {
        for a in self {
            if let SessionAttribute::Fingerprint(v) = a {
                return Some(v);
            }
        }
        None
    }
}

/// Session info, before the first m= line
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub bw: Option<Bandwidth>,
    pub attrs: Vec<SessionAttribute>,
}

/// Session id from o= line
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

/// Bandwidth from b= line
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bandwidth {
    pub typ: String,
    pub val: String,
}

/// Attributes before the first m= line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAttribute {
    Group {
        typ: String,       // BUNDLE, LS etc
        mids: Vec<String>, // 0 1 2 3
    },
    IceLite,
    IceUfrag(String),
    IcePwd(String),
    IceOptions(String),
    Fingerprint(Fingerprint),
    Setup(String), // active, passive, actpass, holdconn
    Candidate(Candidate),
    EndOfCandidates,
    Unused(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub hash_func: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub found: String,         // 1-32 "ice chars", ALPHA / DIGIT / "+" / "/"
    pub comp_id: String,       // 1 for RTP, 2 for RTCP
    pub proto: String,         // udp/tcp
    pub prio: u32,             // 1-10 digits
    pub addr: String,          // ip
    pub port: u16,             // port
    pub typ: String,           // host/srflx/prflx/relay
    pub raddr: Option<String>, // ip
    pub rport: Option<u16>,    // port
}

impl Candidate {
    pub fn host_udp(prio: u32, addr: &IpAddr, port: u16) -> Self {
        Candidate {
            found: "1".into(),
            comp_id: "1".into(),
            proto: "udp".into(),
            prio,
            addr: addr.to_string(),
            port,
            typ: "host".into(),
            raddr: None,
            rport: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransceiverInfo {
    pub typ: MediaType,
    pub proto: Proto,
    pub pts: Vec<u8>, // payload types 96 97 125 107 from the m= line
    pub bw: Option<Bandwidth>,
    pub attrs: Vec<MediaAttribute>,
}

impl TransceiverInfo {
    pub fn mid(&self) -> &str {
        self.attrs
            .iter()
            .find_map(|a| {
                if let MediaAttribute::Mid(m) = a {
                    Some(&m[..])
                } else {
                    None
                }
            })
            // guarded by check_consistent
            .unwrap()
    }

    pub fn direction(&self) -> Direction {
        for a in &self.attrs {
            match a {
                MediaAttribute::SendRecv => return Direction::SendRecv,
                MediaAttribute::SendOnly => return Direction::SendOnly,
                MediaAttribute::RecvOnly => return Direction::RecvOnly,
                MediaAttribute::Inactive => return Direction::Inactive,
                _ => {}
            }
        }
        // Should we error here?
        Direction::Inactive
    }

    pub fn check_consistent(&self) -> Option<String> {
        let mid_count = self
            .attrs
            .iter()
            .filter(|a| matches!(a, MediaAttribute::Mid(_)))
            .count();

        if mid_count == 0 {
            return Some(format!(
                "Media is missing a=mid: {} {}",
                self.typ, self.proto
            ));
        }

        if mid_count > 1 {
            return Some(format!(
                "Media has more than one a=mid: {} {}",
                self.typ, self.proto
            ));
        }

        let setup = self
            .attrs
            .iter()
            .filter(|a| matches!(a, MediaAttribute::Setup(_)))
            .count();

        if setup != 1 {
            return Some(format!("Expected 1 a=setup: line: {}", setup));
        }

        if self.pts.is_empty() {
            return Some("Expected at least one m-line".to_string());
        }

        for m in &self.pts {
            let rtp_count = self
                .attrs
                .iter()
                .filter(|a| {
                    if let MediaAttribute::RtpMap { pt, .. } = a {
                        pt == m
                    } else {
                        false
                    }
                })
                .count();
            if rtp_count == 0 {
                return Some(format!("Missing a=rtp_map:{}", m));
            }
            if rtp_count > 1 {
                return Some(format!("More than one a=rtp_map:{}", m));
            }
        }
        None
    }

    pub fn restrictions(&self) -> Vec<Restriction> {
        let mut restr = vec![];

        for a in &self.attrs {
            if let MediaAttribute::Rid {
                stream_id,
                direction,
                pt,
                restriction,
            } = a
            {
                restr.push(Restriction::new(stream_id, direction, pt, restriction));
            }
        }

        restr
    }

    pub fn ssrc_info(&self) -> Vec<SsrcInfo> {
        self.attrs.ssrc_info()
    }

    pub fn simulcast(&self) -> Option<Simulcast> {
        for a in &self.attrs {
            if let MediaAttribute::Simulcast(s) = a {
                return Some(s.clone());
            }
        }

        // Fallback simulcast for browser doing SDP munging.
        //
        // # MUNGING!
        //
        // Original from browser:
        //
        // a=ssrc:659652645 cname:Taj3/ieCnLbsUFoH
        // a=ssrc:659652645 msid:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk 028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:659652645 mslabel:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk
        // a=ssrc:659652645 label:028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:98148385 cname:Taj3/ieCnLbsUFoH
        // a=ssrc:98148385 msid:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk 028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:98148385 mslabel:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk
        // a=ssrc:98148385 label:028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc-group:FID 659652645 98148385
        //
        // Munged to enable simulcast is done by creating new SSRC for the
        // simulcast layers and communicating it in a a=ssrc-group:SIM.
        // The layers are in order from low to high bitrate.
        //
        // a=ssrc:659652645 cname:Taj3/ieCnLbsUFoH
        // a=ssrc:659652645 msid:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk 028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:659652645 mslabel:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk
        // a=ssrc:659652645 label:028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:98148385 cname:Taj3/ieCnLbsUFoH
        // a=ssrc:98148385 msid:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk 028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:98148385 mslabel:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk
        // a=ssrc:98148385 label:028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:1982135572 cname:Taj3/ieCnLbsUFoH
        // a=ssrc:1982135572 msid:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk 028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:1982135572 mslabel:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk
        // a=ssrc:1982135572 label:028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:2523084908 cname:Taj3/ieCnLbsUFoH
        // a=ssrc:2523084908 msid:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk 028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:2523084908 mslabel:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk
        // a=ssrc:2523084908 label:028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:3604909222 cname:Taj3/ieCnLbsUFoH
        // a=ssrc:3604909222 msid:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk 028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:3604909222 mslabel:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk
        // a=ssrc:3604909222 label:028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:1893605472 cname:Taj3/ieCnLbsUFoH
        // a=ssrc:1893605472 msid:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk 028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc:1893605472 mslabel:i1zOaprU7rZzMDaOXFdqwkq7Q6wP6f3cgUgk
        // a=ssrc:1893605472 label:028ab73b-cdd0-4b61-a282-ea0ed0c6a9bb
        // a=ssrc-group:SIM 659652645 1982135572 3604909222
        // a=ssrc-group:FID 659652645 98148385
        // a=ssrc-group:FID 1982135572 2523084908
        // a=ssrc-group:FID 3604909222 1893605472
        //
        for a in &self.attrs {
            if let MediaAttribute::SsrcGroup { semantics, ssrcs } = a {
                if semantics != "SIM" {
                    continue;
                }

                let group = SimulcastGroup(
                    ssrcs
                        .iter()
                        .map(|ssrc| SimulcastOption::Ssrc(*ssrc))
                        .collect(),
                );

                return Some(Simulcast {
                    recv: SimulcastGroups(vec![]),
                    send: SimulcastGroups(vec![group]),
                    is_munged: true,
                });
            }
        }

        None
    }

    pub fn formats(&self, restr: &[Restriction]) -> Vec<Format> {
        let mut v = vec![];

        for m in &self.pts {
            let mut format = self
                .attrs
                .iter()
                .find_map(|a| {
                    if let MediaAttribute::RtpMap {
                        pt,
                        codec,
                        clock_rate,
                        enc_param,
                    } = a
                    {
                        if pt == m {
                            return Some(Format {
                                pt: *pt,
                                codec: codec.clone(),
                                clock_rate: *clock_rate,
                                enc_param: enc_param.clone(),
                                rtcp_fb: vec![],
                                fmtp: vec![],
                                restrictions: vec![],
                            });
                        }
                    }
                    None
                })
                .unwrap(); // since we did check_consistent()

            // Fill in created Format with additional attributes
            for a in &self.attrs {
                if let MediaAttribute::RtcpFb { pt, value } = a {
                    if pt == m {
                        format.rtcp_fb.push(value.clone());
                    }
                }

                if let MediaAttribute::Fmtp { pt, values } = a {
                    if pt == m {
                        for (k, v) in values {
                            format.fmtp.push((k.clone(), v.clone()));
                        }
                    }
                }
            }

            // Restrictions that apply to this format.
            for r in restr {
                if r.pts.is_empty() || r.pts.contains(m) {
                    format.restrictions.push(r.stream_id.clone());
                }
            }

            v.push(format);
        }
        v
    }
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
        matches!(self, Direction::RecvOnly | Direction::SendRecv)
    }
}

/// One format from an m-section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Format {
    /// payload type (PT) number.
    pub pt: u8,
    /// Codec from `a=rtpmap:<no> codec/<clock-rate>` line
    pub codec: String,
    /// Clock rate from `a=rtpmap:<no> codec/<clock-rate>` line
    pub clock_rate: u32,
    /// Optional encoding parameters from `a=rtpmap:<no> codec/<clock-rate>/<enc-param>` line
    pub enc_param: Option<String>,
    /// Options from `a=rtcp_fb` lines.
    pub rtcp_fb: Vec<String>,
    /// Extra format parameters from the `a=fmtp` line.
    pub fmtp: Vec<(String, String)>,
    /// Restrictions that applies to this format from the `a=rid` lines.
    pub restrictions: Vec<StreamId>,
}

/// Identifier of an RTP stream.
///
/// Defined in https://tools.ietf.org/html/draft-ietf-avtext-rid-09
/// Communicated in SDES and places like a=rid:<here>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamId(pub String);

impl Default for StreamId {
    fn default() -> Self {
        StreamId("".to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Restriction {
    /// The stream id this restriction is for. Unique within the m-section.
    stream_id: StreamId,
    /// "send" or "recv"
    direction: &'static str,
    /// Payload types (PT) this restriction applies to. Empty means all.
    /// (This is pt=1,2,3).
    pts: Vec<u8>,
    /// In pixels
    max_width: Option<u32>,
    /// In pixels
    max_height: Option<u32>,
    /// Frame rate in frames per second
    max_fps: Option<u32>,
    /// Frame size in pixels per frame. Width * height.
    max_fs: Option<u32>,
    /// Bit rate in bits per second.
    max_br: Option<u32>,
    /// Pixel rate, pixels per second.
    ///
    /// Calculated as an average of all samples of any given coded picture.
    /// This is expressed as a floating point value, with an allowed range of
    /// 0.0001 to 48.0. These values MUST NOT be encoded with more than
    /// four digits to the right of the decimal point.
    max_pps: Option<F32Eq>,
    /// Bits per pixel.
    max_bpp: Option<u32>,
    /// Other streams this stream depends on.
    depend: Option<Vec<StreamId>>,
}

impl Restriction {
    fn new(
        stream_id: &str,
        direction: &'static str,
        pt: &[u8],
        restriction: &[(String, String)],
    ) -> Self {
        let mut r = Restriction {
            ..Default::default()
        };
        r.stream_id = StreamId(stream_id.to_string());
        r.direction = direction;
        r.pts = pt.to_vec();

        for (k, v) in restriction {
            match &k[..] {
                "max-width" => r.max_width = v.parse::<u32>().ok(),
                "max-height" => r.max_height = v.parse::<u32>().ok(),
                "max-fps" => r.max_fps = v.parse::<u32>().ok(),
                "max-fs" => r.max_fs = v.parse::<u32>().ok(),
                "max-br" => r.max_br = v.parse::<u32>().ok(),
                "max-pps" => r.max_pps = v.parse::<F32Eq>().ok(),
                "max-bpp" => r.max_bpp = v.parse::<u32>().ok(),
                "depend" => {
                    r.depend = Some(v.split(',').map(|i| StreamId(i.to_string())).collect())
                }
                _ => {
                    debug!("Unrecognized a=rid restriction {}={}", k, v);
                }
            }
        }

        r
    }

    pub fn to_media_attr(&self) -> MediaAttribute {
        let mut restriction = vec![];

        if let Some(v) = self.max_width {
            restriction.push(("max-width".to_string(), v.to_string()));
        }
        if let Some(v) = self.max_height {
            restriction.push(("max-height".to_string(), v.to_string()));
        }
        if let Some(v) = self.max_fps {
            restriction.push(("max-fps".to_string(), v.to_string()));
        }
        if let Some(v) = self.max_fs {
            restriction.push(("max-fs".to_string(), v.to_string()));
        }
        if let Some(v) = self.max_br {
            restriction.push(("max-br".to_string(), v.to_string()));
        }
        if let Some(v) = self.max_pps {
            let x = (v.0 * 10_000.0).round() / 10_000.0;
            restriction.push(("max-pps".to_string(), x.to_string()));
        }
        if let Some(v) = self.max_bpp {
            restriction.push(("max-bpp".to_string(), v.to_string()));
        }
        if let Some(v) = &self.depend {
            restriction.push((
                "depend".to_string(),
                v.iter()
                    .map(|s| &s.0)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }

        MediaAttribute::Rid {
            stream_id: self.stream_id.0.to_string(),
            direction: self.direction,
            pt: self.pts.clone(),
            restriction,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct F32Eq(f32);

impl PartialEq for F32Eq {
    fn eq(&self, other: &Self) -> bool {
        (self.0 - other.0).abs() < 0.00000000001
    }
}
impl Eq for F32Eq {}

impl FromStr for F32Eq {
    type Err = ParseFloatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(F32Eq(s.parse()?))
    }
}

/// "audio", "video", "application"
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaType {
    Audio,
    Video,
    Application,
    Unknown(String),
}

/// UDP/TLS/RTP/SAVPF or DTLS/SCTP
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proto(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtMap {
    pub id: u8,                    // 1-14 inclusive, 0 and 15 are reserved.
    pub direction: Option<String>, // recvonly, sendrecv, sendonly
    pub ext_type: RtpExtensionType,
    pub ext: Option<String>,
}

/// Attributes before the first m= line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaAttribute {
    // The "a=rtcp" line MUST NOT be added if the most recent answer included an "a=rtcp-mux" line.
    Rtcp(String),
    IceUfrag(String),
    IcePwd(String),
    IceOptions(String),
    Fingerprint(Fingerprint),
    Setup(String), // active, passive, actpass, holdconn
    Mid(String),   // 0, 1, 2
    // a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
    // a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
    ExtMap(ExtMap),
    RecvOnly, // a=recvonly
    SendRecv, // a=sendrecv
    SendOnly, // a=sendonly
    Inactive, // a=inactive
    // a=msid:5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK f78dde68-7055-4e20-bb37-433803dd1ed1
    // a=msid:- 78dde68-7055-4e20-bb37-433803dd1ed1
    Msid {
        stream_id: String,
        track_id: String,
    },
    RtcpMux,
    RtcpMuxOnly,
    // reduced size rtcp. remove this if not supported.
    RtcpRsize,
    Candidate(Candidate),
    EndOfCandidates,
    RtpMap {
        pt: u8,                    // 111
        codec: String,             // opus
        clock_rate: u32,           // 48000
        enc_param: Option<String>, // 2 (audio number of channels)
    },
    // rtcp-fb RTCP feedback parameters, repeated
    RtcpFb {
        pt: u8,        // 111
        value: String, // nack, nack pli, ccm fir...
    },
    // format parameters, seems to be one of these
    Fmtp {
        pt: u8,                        // 111
        values: Vec<(String, String)>, // minptime=10;useinbandfec=1
    },
    // a=rid:<rid-id> <direction> [pt=<fmt-list>;]<restriction>=<value>
    // a=rid:hi send pt=111,112;max-br=64000;max-height=360
    // https://tools.ietf.org/html/draft-ietf-mmusic-rid-15
    Rid {
        stream_id: String, // StreamId and RepairStreamId as in SDES or RTP header ext.
        direction: &'static str, // send or recv
        // No pt means the rid applies to all
        pt: Vec<u8>, // 111, 112 (rtpmap no)
        restriction: Vec<(String, String)>,
    },
    // a=rid:hi send
    // a=rid:lo send
    // a=simulcast:send hi;lo
    // https://tools.ietf.org/html/draft-ietf-mmusic-sdp-simulcast-14
    // a=simulcast:<send/recv> <alt A>;<alt B>,<or C> <send/recv> [same]
    Simulcast(Simulcast),
    SsrcGroup {
        semantics: String, // i.e. "FID"
        ssrcs: Vec<u32>,   // <normal stream> <repair stream>
    },
    Ssrc {
        ssrc: u32, // synchronization source id
        attr: String,
        value: String,
    },
    Unused(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Simulcast {
    pub send: SimulcastGroups,
    pub recv: SimulcastGroups,
    /// If this is created synthentically for a munged SDP.
    pub is_munged: bool,
}

impl Simulcast {
    pub fn flip(self) -> Self {
        Simulcast {
            send: self.recv,
            recv: self.send,
            is_munged: self.is_munged,
        }
    }
}

/// RID organization inside a=simulcast line.
///
/// `a=simulcast send 2;3,4` would result in
/// `SimulcastGroups(SimulcastGroup(2,3), SimulcastGroup(4))`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulcastGroups(pub Vec<SimulcastGroup>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulcastGroup(pub Vec<SimulcastOption>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimulcastOption {
    StreamId(StreamId),
    Ssrc(u32),
}

impl SimulcastOption {
    pub fn as_stream_id(&self) -> &StreamId {
        if let SimulcastOption::StreamId(stream_id) = self {
            stream_id
        } else {
            panic!("as_stream_id on SimulcastOption::Ssrc");
        }
    }
}

impl fmt::Display for SimulcastGroups {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, a) in self.0.iter().enumerate() {
            if idx + 1 == self.0.len() {
                write!(f, "{}", a)?;
            } else {
                write!(f, "{},", a)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for SimulcastGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, a) in self.0.iter().enumerate() {
            if idx + 1 == self.0.len() {
                write!(f, "{}", a.as_stream_id().0)?;
            } else {
                write!(f, "{};", a.as_stream_id().0)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Sdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.session)?;
        for m in &self.transceivers {
            write!(f, "{}", m)?;
        }
        Ok(())
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v=0\r\n")?;
        write!(f, "o=- {} 2 IN IP4 127.0.0.1\r\n", self.id.0)?;
        write!(f, "s=-\r\n")?;
        if let Some(bw) = &self.bw {
            write!(f, "b={}:{}\r\n", bw.typ, bw.val)?;
        }
        write!(f, "t=0 0\r\n")?;
        for a in &self.attrs {
            write!(f, "{}", a)?;
        }
        Ok(())
    }
}

impl fmt::Display for SessionAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SessionAttribute::*;
        match self {
            Group { typ, mids } => write!(f, "a=group:{} {}\r\n", typ, mids.join(" "))?,
            IceLite => write!(f, "a=ice-lite\r\n")?,
            IceUfrag(v) => write!(f, "a=ice-ufrag:{}\r\n", v)?,
            IcePwd(v) => write!(f, "a=ice-pwd:{}\r\n", v)?,
            IceOptions(v) => write!(f, "a=ice-options:{}\r\n", v)?,
            Fingerprint(v) => {
                write!(
                    f,
                    "a=fingerprint:{} {}\r\n",
                    v.hash_func,
                    FingerprintFmt(&v.bytes)
                )?;
            }
            Setup(v) => write!(f, "a=setup:{}\r\n", v)?,
            Candidate(c) => write!(f, "{}", c)?,
            EndOfCandidates => write!(f, "a=end-of-candidates\r\n")?,
            Unused(v) => write!(f, "a={}\r\n", v)?,
        }
        Ok(())
    }
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a=candidate:{} {} {} {} {} {} typ {}",
            self.found, self.comp_id, self.proto, self.prio, self.addr, self.port, self.typ
        )?;
        if let (Some(raddr), Some(rport)) = (self.raddr.as_ref(), self.rport.as_ref()) {
            write!(f, " raddr {} rport {}", raddr, rport)?;
        }
        write!(f, "\r\n")
    }
}

impl fmt::Display for TransceiverInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m={} 9 {} ", self.typ, self.proto,)?;
        let len = self.pts.len();
        for (idx, m) in self.pts.iter().enumerate() {
            if idx + 1 < len {
                write!(f, "{} ", m)?;
            } else {
                write!(f, "{}\r\n", m)?;
            }
        }
        write!(f, "c=IN IP4 0.0.0.0\r\n")?;
        if let Some(bw) = &self.bw {
            write!(f, "b={}:{}\r\n", bw.typ, bw.val)?;
        }
        for a in &self.attrs {
            write!(f, "{}", a)?;
        }
        Ok(())
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediaType::Audio => write!(f, "audio"),
            MediaType::Video => write!(f, "video"),
            MediaType::Application => write!(f, "application"),
            MediaType::Unknown(v) => write!(f, "{}", v),
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for MediaAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MediaAttribute::*;
        match self {
            Rtcp(v) => write!(f, "a=rtcp:{}\r\n", v)?,
            IceUfrag(v) => write!(f, "a=ice-ufrag:{}\r\n", v)?,
            IcePwd(v) => write!(f, "a=ice-pwd:{}\r\n", v)?,
            IceOptions(v) => write!(f, "a=ice-options:{}\r\n", v)?,
            Fingerprint(v) => {
                write!(
                    f,
                    "a=fingerprint:{} {}\r\n",
                    v.hash_func,
                    FingerprintFmt(&v.bytes)
                )?;
            }
            Setup(v) => write!(f, "a=setup:{}\r\n", v)?,
            Mid(v) => write!(f, "a=mid:{}\r\n", v)?,
            ExtMap(e) => {
                if e.ext_type.is_filtered() {
                    return Ok(());
                }
                write!(f, "a=extmap:{}", e.id)?;
                if let Some(d) = &e.direction {
                    write!(f, "/{}", d)?;
                }
                write!(f, " {}", e.ext_type.as_uri())?;
                if let Some(e) = &e.ext {
                    write!(f, " {}", e)?;
                }
                write!(f, "\r\n")?;
            }
            RecvOnly => write!(f, "a=recvonly\r\n")?,
            SendRecv => write!(f, "a=sendrecv\r\n")?,
            SendOnly => write!(f, "a=sendonly\r\n")?,
            Inactive => write!(f, "a=inactive\r\n")?,
            // a=msid:5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK f78dde68-7055-4e20-bb37-433803dd1ed1
            // a=msid:- 78dde68-7055-4e20-bb37-433803dd1ed1
            Msid {
                stream_id,
                track_id,
            } => write!(f, "a=msid:{} {}\r\n", stream_id, track_id)?,
            RtcpMux => write!(f, "a=rtcp-mux\r\n")?,
            RtcpMuxOnly => write!(f, "a=rtcp-mux-only\r\n")?,
            RtcpRsize => write!(f, "a=rtcp-rsize\r\n")?,
            Candidate(c) => write!(f, "{}", c)?,
            EndOfCandidates => write!(f, "a=end-of-candidates\r\n")?,
            RtpMap {
                pt,
                codec,
                clock_rate,
                enc_param,
            } => {
                write!(f, "a=rtpmap:{} {}/{}", pt, codec, clock_rate)?;
                if let Some(e) = enc_param {
                    write!(f, "/{}", e)?;
                }
                write!(f, "\r\n")?;
            }
            RtcpFb { pt, value } => write!(f, "a=rtcp-fb:{} {}\r\n", pt, value)?,
            Fmtp { pt, values } => {
                write!(f, "a=fmtp:{} ", pt)?;
                for (idx, (k, v)) in values.iter().enumerate() {
                    if idx + 1 < values.len() {
                        write!(f, "{}={};", k, v)?;
                    } else {
                        write!(f, "{}={}\r\n", k, v)?;
                    }
                }
            }
            // a=rid:hi send pt=111,112;max-br=64000;max-height=360
            Rid {
                stream_id,
                direction,
                pt,
                restriction,
            } => {
                write!(f, "a=rid:{} {}", stream_id, direction)?;
                for (idx, p) in pt.iter().enumerate() {
                    if idx == 0 {
                        write!(f, " pt=")?;
                    }
                    if idx + 1 == pt.len() {
                        write!(f, "{}", p)?;
                    } else {
                        write!(f, "{},", p)?;
                    }
                }
                for (idx, (k, v)) in restriction.iter().enumerate() {
                    if idx == 0 {
                        if pt.is_empty() {
                            write!(f, " ")?;
                        } else {
                            write!(f, ";")?;
                        }
                    }
                    if idx + 1 == restriction.len() {
                        write!(f, "{}={}", k, v)?;
                    } else {
                        write!(f, "{}={};", k, v)?;
                    }
                }
                write!(f, "\r\n")?;
            }
            // a=simulcast:<send/recv> <alt A>;<alt B>,<or C> <send/recv> [same]
            Simulcast(x) => {
                let self::Simulcast {
                    send,
                    recv,
                    is_munged,
                } = x;
                assert!(
                    !(send.0.is_empty() && recv.0.is_empty()),
                    "Empty a=simulcast"
                );
                if *is_munged {
                    // dont' write
                    return Ok(());
                }
                write!(f, "a=simulcast:")?;
                if !send.0.is_empty() {
                    write!(f, "send {}", send)?;
                }
                if !recv.0.is_empty() {
                    if !send.0.is_empty() {
                        write!(f, " ")?;
                    }
                    write!(f, "recv {}", recv)?;
                }
                write!(f, "\r\n")?;
            }
            SsrcGroup { semantics, ssrcs } => {
                write!(f, "a=ssrc-group:{} ", semantics)?;
                for (idx, ssrc) in ssrcs.iter().enumerate() {
                    if idx + 1 < ssrcs.len() {
                        write!(f, "{} ", ssrc)?;
                    } else {
                        write!(f, "{}\r\n", ssrc)?;
                    }
                }
            }
            Ssrc { ssrc, attr, value } => {
                write!(f, "a=ssrc:{} {}:{}\r\n", ssrc, attr, value)?;
            }
            Unused(v) => write!(f, "a={}\r\n", v)?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RtpExtensionType {
    AbsoluteSendTime,
    AudioLevel,
    /// Use when a RTP packet is delayed by a send queue to indicate an offset in the "transmitter".
    /// It effectively means we can set a timestamp offset exactly when the UDP packet leaves the
    /// server.
    TransmissionTimeOffset,
    VideoOrientation,
    TransportSequenceNumber,
    PlayoutDelay,
    VideoContentType,
    VideoTiming,
    /// UTF8 encoded identifier for the RTP stream. Not the same as SSRC, this is is designed to
    /// avoid running out of SSRC for very large sessions.
    RtpStreamId,
    /// UTF8 encoded identifier referencing another RTP stream's RtpStreamId. If we see
    /// this extension type, we know the stream is a repair stream.
    RepairedRtpStreamId,
    RtpMid,
    FrameMarking,
    ColorSpace,
    UnknownUri,
    UnknownExt,
}
/// Mapping of extension URI to our enum
const RTP_EXT_URI: &[(RtpExtensionType, &str)] = &[
    (
        RtpExtensionType::AbsoluteSendTime,
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
    ),
    (
        RtpExtensionType::AudioLevel,
        "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
    ),
    (
        RtpExtensionType::TransmissionTimeOffset,
        "urn:ietf:params:rtp-hdrext:toffset",
    ),
    (
        RtpExtensionType::VideoOrientation,
        "urn:3gpp:video-orientation",
    ),
    (
        RtpExtensionType::TransportSequenceNumber,
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    ),
    (
        RtpExtensionType::PlayoutDelay,
        "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
    ),
    (
        RtpExtensionType::VideoContentType,
        "http://www.webrtc.org/experiments/rtp-hdrext/video-content-type",
    ),
    (
        RtpExtensionType::VideoTiming,
        "http://www.webrtc.org/experiments/rtp-hdrext/video-timing",
    ),
    (
        RtpExtensionType::RtpStreamId,
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
    ),
    (
        RtpExtensionType::RepairedRtpStreamId,
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ),
    (
        RtpExtensionType::RtpMid,
        "urn:ietf:params:rtp-hdrext:sdes:mid",
    ),
    (
        RtpExtensionType::FrameMarking,
        "http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07",
    ),
    (
        RtpExtensionType::ColorSpace,
        "http://www.webrtc.org/experiments/rtp-hdrext/color-space",
    ),
];

impl RtpExtensionType {
    pub fn from_uri(uri: &str) -> Self {
        for (t, spec) in RTP_EXT_URI.iter() {
            if *spec == uri {
                return *t;
            }
        }

        trace!("Unknown a=extmap uri: {}", uri);

        RtpExtensionType::UnknownUri
    }

    pub fn as_uri(&self) -> &'static str {
        for (t, spec) in RTP_EXT_URI.iter() {
            if t == self {
                return spec;
            }
        }
        "unknown"
    }

    pub fn is_supported(&self) -> bool {
        use RtpExtensionType::*;
        match self {
            // These 4 seem to be the bare minimum to get Chrome
            // to send RTP for a simulcast video
            RtpStreamId => true,
            RepairedRtpStreamId => true,
            RtpMid => true,
            AbsoluteSendTime => true,
            VideoOrientation => true,
            AudioLevel => true,

            // transport wide cc
            TransportSequenceNumber => true,

            TransmissionTimeOffset => false,
            PlayoutDelay => false,
            VideoContentType => false,
            VideoTiming => false,
            FrameMarking => false,
            ColorSpace => false,
            UnknownUri => false,
            UnknownExt => false,
        }
    }

    pub fn is_filtered(&self) -> bool {
        use RtpExtensionType::*;
        matches!(self, UnknownUri | UnknownExt)
    }
}

pub struct FingerprintFmt<'a>(pub &'a [u8]);

impl<'a> std::fmt::Display for FingerprintFmt<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let last = self.0.len() - 1;
        for (idx, b) in self.0.iter().enumerate() {
            if idx < last {
                write!(f, "{:02X}:", b)?;
            } else {
                write!(f, "{:02X}", b)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn write_sdp() {
        let sdp = Sdp { session: Session { id: SessionId(5_058_682_828_002_148_772),
            bw: None, attrs:
            vec![SessionAttribute::Group { typ: "BUNDLE".into(), mids: vec!["0".into()] }, SessionAttribute::Unused("msid-semantic: WMS 5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK".into())] },
            transceivers: vec![
                TransceiverInfo {
                    typ: MediaType::Audio,
                    proto: Proto("UDP/TLS/RTP/SAVPF".into()),
                    pts: vec![111, 103, 104, 9, 0, 8, 106, 105, 13, 110, 112, 113, 126],
                    bw: None,
                    attrs: vec![
                        MediaAttribute::Rtcp("9 IN IP4 0.0.0.0".into()),
                        MediaAttribute::IceUfrag("S5hk".into()),
                        MediaAttribute::IcePwd("0zV/Yu3y8aDzbHgqWhnVQhqP".into()),
                        MediaAttribute::IceOptions("trickle".into()),
                        MediaAttribute::Fingerprint(Fingerprint { hash_func: "sha-256".into(), bytes: vec![140, 100, 237, 3, 118, 208, 61, 180, 136, 8, 145, 100, 8, 128, 168, 198, 90, 191, 139, 78, 56, 39, 150, 202, 8, 73, 37, 115, 70, 96, 32, 220] }),
                        MediaAttribute::Setup("actpass".into()),
                        MediaAttribute::Mid("0".into()),
                        MediaAttribute::ExtMap(ExtMap { id: 1, direction: None, ext_type: RtpExtensionType::AudioLevel, ext: None }),
                        MediaAttribute::ExtMap(ExtMap { id: 2, direction: None, ext_type: RtpExtensionType::AbsoluteSendTime, ext: None }),
                        MediaAttribute::ExtMap(ExtMap { id: 3, direction: None, ext_type: RtpExtensionType::TransportSequenceNumber, ext: None }),
                        MediaAttribute::ExtMap(ExtMap { id: 4, direction: None, ext_type: RtpExtensionType::RtpMid, ext: None }),
                        MediaAttribute::ExtMap(ExtMap { id: 5, direction: None, ext_type: RtpExtensionType::RtpStreamId, ext: None }),
                        MediaAttribute::ExtMap(ExtMap { id: 6, direction: None, ext_type: RtpExtensionType::RepairedRtpStreamId, ext: None }),
                        MediaAttribute::SendRecv,
                        MediaAttribute::Msid { stream_id: "5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK".into(), track_id: "f78dde68-7055-4e20-bb37-433803dd1ed1".into() },
                        MediaAttribute::RtcpMux,
                        MediaAttribute::RtpMap { pt: 111, codec: "opus".into(), clock_rate: 48_000, enc_param: Some("2".into()) },
                        MediaAttribute::RtcpFb { pt: 111, value: "transport-cc".into() },
                        MediaAttribute::Fmtp { pt: 111, values: vec![("minptime".into(), "10".into()), ("useinbandfec".into(), "1".into())] },
                        MediaAttribute::RtpMap { pt: 103, codec: "ISAC".into(), clock_rate: 16_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 104, codec: "ISAC".into(), clock_rate: 32_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 9, codec: "G722".into(), clock_rate: 8_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 0, codec: "PCMU".into(), clock_rate: 8_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 8, codec: "PCMA".into(), clock_rate: 8_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 106, codec: "CN".into(), clock_rate: 32_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 105, codec: "CN".into(), clock_rate: 16_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 13, codec: "CN".into(), clock_rate: 8_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 110, codec: "telephone-event".into(), clock_rate: 48_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 112, codec: "telephone-event".into(), clock_rate: 32_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 113, codec: "telephone-event".into(), clock_rate: 16_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 126, codec: "telephone-event".into(), clock_rate: 8_000, enc_param: None },
                        MediaAttribute::Ssrc { ssrc: 3_948_621_874, attr: "cname".into(), value: "xeXs3aE9AOBn00yJ".into() },
                        MediaAttribute::Ssrc { ssrc: 3_948_621_874, attr: "msid".into(), value: "5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK f78dde68-7055-4e20-bb37-433803dd1ed1".into() },
                        MediaAttribute::Ssrc { ssrc: 3_948_621_874, attr: "mslabel".into(), value: "5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK".into() },
                        MediaAttribute::Ssrc { ssrc: 3_948_621_874, attr: "label".into(), value: "f78dde68-7055-4e20-bb37-433803dd1ed1".into() }] }] };
        assert_eq!(&format!("{}", sdp), "v=0\r\n\
            o=- 5058682828002148772 2 IN IP4 127.0.0.1\r\n\
            s=-\r\n\
            t=0 0\r\n\
            a=group:BUNDLE 0\r\n\
            a=msid-semantic: WMS 5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK\r\n\
            m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126\r\n\
            c=IN IP4 0.0.0.0\r\n\
            a=rtcp:9 IN IP4 0.0.0.0\r\n\
            a=ice-ufrag:S5hk\r\n\
            a=ice-pwd:0zV/Yu3y8aDzbHgqWhnVQhqP\r\n\
            a=ice-options:trickle\r\n\
            a=fingerprint:sha-256 8C:64:ED:03:76:D0:3D:B4:88:08:91:64:08:80:A8:C6:5A:BF:8B:4E:38:27:96:CA:08:49:25:73:46:60:20:DC\r\n\
            a=setup:actpass\r\n\
            a=mid:0\r\n\
            a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
            a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n\
            a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n\
            a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
            a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n\
            a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n\
            a=sendrecv\r\n\
            a=msid:5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK f78dde68-7055-4e20-bb37-433803dd1ed1\r\n\
            a=rtcp-mux\r\n\
            a=rtpmap:111 opus/48000/2\r\n\
            a=rtcp-fb:111 transport-cc\r\n\
            a=fmtp:111 minptime=10;useinbandfec=1\r\n\
            a=rtpmap:103 ISAC/16000\r\n\
            a=rtpmap:104 ISAC/32000\r\n\
            a=rtpmap:9 G722/8000\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=rtpmap:8 PCMA/8000\r\n\
            a=rtpmap:106 CN/32000\r\n\
            a=rtpmap:105 CN/16000\r\n\
            a=rtpmap:13 CN/8000\r\n\
            a=rtpmap:110 telephone-event/48000\r\n\
            a=rtpmap:112 telephone-event/32000\r\n\
            a=rtpmap:113 telephone-event/16000\r\n\
            a=rtpmap:126 telephone-event/8000\r\n\
            a=ssrc:3948621874 cname:xeXs3aE9AOBn00yJ\r\n\
            a=ssrc:3948621874 msid:5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK f78dde68-7055-4e20-bb37-433803dd1ed1\r\n\
            a=ssrc:3948621874 mslabel:5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK\r\n\
            a=ssrc:3948621874 label:f78dde68-7055-4e20-bb37-433803dd1ed1\r\n\
            ");
    }
}
