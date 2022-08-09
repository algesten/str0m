use combine::Parser;
use dtls::Fingerprint;
use rtp::{ExtMap, Mid};
use std::fmt::{self};
use std::hash::Hash;
use std::num::ParseFloatError;
use std::str::FromStr;

use ice::{Candidate, IceCreds};
use rtp::Pt;

use super::parser::sdp_parser;
use super::SdpError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sdp {
    pub session: Session,
    pub media_lines: Vec<MediaLine>,
}

impl Sdp {
    pub fn parse(input: &str) -> Result<Sdp, SdpError> {
        Ok(sdp_parser().parse(input).map(|(sdp, _)| sdp)?)
    }

    pub fn assert_consistency(&self) -> Result<(), SdpError> {
        match self.do_assert_consistency() {
            None => Ok(()),
            Some(error) => Err(SdpError::Inconsistent(error)),
        }
    }

    fn do_assert_consistency(&self) -> Option<String> {
        let group = self
            .session
            .attrs
            .iter()
            .find(|a| matches!(a, SessionAttribute::Group { .. }));

        if let Some(SessionAttribute::Group { mids, .. }) = group {
            if !mids.len() == self.media_lines.len() {
                return Some(format!("a=group mid count doesn't match m-line count"));
            }
            for (m_line, mid) in self.media_lines.iter().zip(mids.iter()) {
                m_line.check_consistent()?;
                let m = m_line.mid();
                if m != *mid {
                    return Some(format!("Mid order not matching a=group {} != {}", m, mid));
                }
            }
        } else {
            return Some("Session attribute a=group missing".into());
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

/// Bandwidth from b= line
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bandwidth {
    pub typ: String,
    pub val: String,
}

impl Session {
    pub fn setup(&self) -> Option<Setup> {
        let setup = self.attrs.iter().find_map(|m| {
            if let SessionAttribute::Setup(v) = m {
                Some(v)
            } else {
                None
            }
        })?;

        Some(*setup)
    }

    pub fn ice_creds(&self) -> Option<IceCreds> {
        let ufrag = self.attrs.iter().find_map(|m| {
            if let SessionAttribute::IceUfrag(v) = m {
                Some(v)
            } else {
                None
            }
        })?;

        let pass = self.attrs.iter().find_map(|m| {
            if let SessionAttribute::IcePwd(v) = m {
                Some(v)
            } else {
                None
            }
        })?;

        Some(IceCreds {
            ufrag: ufrag.to_string(),
            pass: pass.to_string(),
        })
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        for a in &self.attrs {
            if let SessionAttribute::Fingerprint(v) = a {
                return Some(v.clone());
            }
        }
        None
    }

    pub fn ice_lite(&self) -> bool {
        self.attrs
            .iter()
            .any(|a| matches!(a, SessionAttribute::IceLite))
    }

    pub fn ice_candidates(&self) -> impl Iterator<Item = &Candidate> {
        self.attrs.iter().filter_map(|a| {
            if let SessionAttribute::Candidate(v) = a {
                Some(v)
            } else {
                None
            }
        })
    }

    pub fn end_of_candidates(&self) -> bool {
        self.attrs
            .iter()
            .any(|a| matches!(a, SessionAttribute::EndOfCandidates))
    }
}

/// Attributes before the first m= line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAttribute {
    Group {
        typ: String,    // BUNDLE, LS etc
        mids: Vec<Mid>, // 0 1 2 3
    },
    IceLite,
    IceUfrag(String),
    IcePwd(String),
    IceOptions(String),
    Fingerprint(Fingerprint),
    Setup(Setup), // active, passive, actpass, holdconn
    Candidate(Candidate),
    EndOfCandidates,
    Unused(String),
}

fn is_dir(a: &MediaAttribute) -> bool {
    use MediaAttribute::*;
    matches!(a, SendRecv | SendOnly | RecvOnly | Inactive)
}

/// An m-line
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MediaLine {
    pub typ: MediaType,
    pub proto: Proto,
    pub pts: Vec<Pt>, // payload types 96 97 125 107 from the m= line
    pub bw: Option<Bandwidth>,
    pub attrs: Vec<MediaAttribute>,
}

impl MediaLine {
    pub fn mid(&self) -> Mid {
        self.attrs
            .iter()
            .find_map(|a| {
                if let MediaAttribute::Mid(m) = a {
                    Some(*m)
                } else {
                    None
                }
            })
            // We should only use `mid()` once we're certain there is
            // a mid line. This is checked by `check_consistent`.
            .expect("missing a=mid")
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

    pub fn set_direction(&mut self, dir: Direction) {
        let idx = self
            .attrs
            .iter()
            .position(is_dir)
            .expect("m-line must have direction");
        self.attrs[idx] = dir.into();
    }

    pub fn check_consistent(&self) -> Option<String> {
        use MediaAttribute::*;

        let mid_count = self.attrs.iter().filter(|a| matches!(a, Mid(_))).count();

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

        let setup = self.attrs.iter().filter(|a| matches!(a, Setup(_))).count();

        if setup != 1 {
            return Some(format!("Expected 1 a=setup: line for mid: {}", self.mid()));
        }

        let dir_count = self.attrs.iter().filter(|a| is_dir(a)).count();

        if dir_count != 1 {
            return Some(format!(
                "Expected exactly one of a=sendrecv, a=sendonly, a=recvonly, a=inactive for mid: {}",
                self.mid()
            ));
        }

        if self.pts.is_empty() {
            return Some(format!("Expected at least one PT for mid: {}", self.mid()));
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
                return Some(format!("Missing a=rtp_map:{} for mid: {}", m, self.mid()));
            }
            if rtp_count > 1 {
                return Some(format!(
                    "More than one a=rtp_map:{} for mid: {}",
                    m,
                    self.mid()
                ));
            }
        }
        None
    }

    pub fn restrictions(&self) -> Vec<Restriction> {
        let mut restr = vec![];

        for a in &self.attrs {
            if let MediaAttribute::Rid {
                id,
                direction,
                pt,
                restriction,
            } = a
            {
                restr.push(Restriction::new(id.clone(), direction, pt, restriction));
            }
        }

        restr
    }

    pub fn setup(&self) -> Option<Setup> {
        let setup = self.attrs.iter().find_map(|m| {
            if let MediaAttribute::Setup(v) = m {
                Some(v)
            } else {
                None
            }
        })?;

        Some(*setup)
    }

    pub fn ice_creds(&self) -> Option<IceCreds> {
        let ufrag = self.attrs.iter().find_map(|m| {
            if let MediaAttribute::IceUfrag(v) = m {
                Some(v)
            } else {
                None
            }
        })?;

        let pass = self.attrs.iter().find_map(|m| {
            if let MediaAttribute::IcePwd(v) = m {
                Some(v)
            } else {
                None
            }
        })?;

        Some(IceCreds {
            ufrag: ufrag.to_string(),
            pass: pass.to_string(),
        })
    }
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        for a in &self.attrs {
            if let MediaAttribute::Fingerprint(v) = a {
                return Some(v.clone());
            }
        }
        None
    }

    /// This hoovers the ice candidates from all m-lines, lots of dupes.
    /// For WebRTC we don't expect different ice states per media line.
    pub fn ice_candidates(&self) -> impl Iterator<Item = &Candidate> {
        self.attrs.iter().filter_map(|a| {
            if let MediaAttribute::Candidate(v) = a {
                Some(v)
            } else {
                None
            }
        })
    }

    /// Any end-of-candidate in any m-line.
    /// For WebRTC we don't expect different ice states per media line.
    pub fn end_of_candidates(&self) -> bool {
        self.attrs
            .iter()
            .any(|a| matches!(a, MediaAttribute::EndOfCandidates))
    }

    pub fn extmaps(&self) -> Vec<ExtMap> {
        let mut ret = vec![];

        for a in &self.attrs {
            if let MediaAttribute::ExtMap(e) = a {
                ret.push(e.clone());
            }
        }

        ret
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
                    format.restrictions.push(r.id.clone());
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
    /// Send only direction.
    SendOnly,
    /// Receive only direction.
    RecvOnly,
    /// Bi-directional.
    SendRecv,
    /// Disabled direction.
    Inactive,
}

impl Direction {
    pub fn invert(&self) -> Self {
        match self {
            Direction::SendOnly => Direction::RecvOnly,
            Direction::RecvOnly => Direction::SendOnly,
            _ => *self,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Direction::SendOnly => "sendonly",
                Direction::RecvOnly => "recvonly",
                Direction::SendRecv => "sendrecv",
                Direction::Inactive => "inactive",
            }
        )
    }
}

impl From<Direction> for MediaAttribute {
    fn from(v: Direction) -> Self {
        match v {
            Direction::SendOnly => MediaAttribute::SendOnly,
            Direction::RecvOnly => MediaAttribute::RecvOnly,
            Direction::SendRecv => MediaAttribute::SendRecv,
            Direction::Inactive => MediaAttribute::Inactive,
        }
    }
}

/// One format from an m-section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Format {
    /// payload type (PT) number.
    pub pt: Pt,

    /// Codec from `a=rtpmap:<no> codec/<clock-rate>` line.
    ///
    /// The uppercase/lowercase of this is weird: `VP8`, `VP9`, `H264`, `opus`.
    pub codec: String,

    /// Clock rate from `a=rtpmap:<no> codec/<clock-rate>` line
    pub clock_rate: u32,

    /// Optional encoding parameters from `a=rtpmap:<no> codec/<clock-rate>/<enc-param>` line
    pub enc_param: Option<String>,

    /// Options from `a=rtcp_fb` lines.
    pub rtcp_fb: Vec<String>,

    /// Extra format parameters from the `a=fmtp:<no>` line.
    pub fmtp: Vec<(String, String)>,

    /// Restrictions that applies to this format from the `a=rid` lines.
    pub restrictions: Vec<RestrictionId>,
}

/// Identifier of an `a=rid` restriction.
///
/// Defined in https://tools.ietf.org/html/draft-ietf-avtext-rid-09
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestrictionId(pub String);

impl RestrictionId {
    pub fn new(v: String) -> Self {
        RestrictionId(v)
    }
}

impl Default for RestrictionId {
    fn default() -> Self {
        RestrictionId("".to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Restriction {
    /// The stream id this restriction is for. Unique within the m-section.
    pub id: RestrictionId,

    /// "send" or "recv"
    pub direction: &'static str,

    /// Payload types (PT) this restriction applies to. Empty means all.
    /// (This is pt=1,2,3).
    pub pts: Vec<Pt>,

    /// In pixels
    pub max_width: Option<u32>,

    /// In pixels
    pub max_height: Option<u32>,

    /// Frame rate in frames per second
    pub max_fps: Option<u32>,

    /// Frame size in pixels per frame. Width * height.
    pub max_fs: Option<u32>,

    /// Bit rate in bits per second.
    pub max_br: Option<u32>,

    /// Pixel rate, pixels per second.
    ///
    /// Calculated as an average of all samples of any given coded picture.
    /// This is expressed as a floating point value, with an allowed range of
    /// 0.0001 to 48.0. These values MUST NOT be encoded with more than
    /// four digits to the right of the decimal point.
    pub max_pps: Option<F32Eq>,

    /// Bits per pixel.
    pub max_bpp: Option<u32>,

    /// Other streams this stream depends on.
    pub depend: Option<Vec<RestrictionId>>,
}

impl Restriction {
    fn new(
        id: RestrictionId,
        direction: &'static str,
        pt: &[Pt],
        restriction: &[(String, String)],
    ) -> Self {
        let mut r = Restriction {
            ..Default::default()
        };
        r.id = id;
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
                    r.depend = Some(v.split(',').map(|i| RestrictionId(i.to_string())).collect())
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
            id: self.id.clone(),
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
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum MediaType {
    #[default]
    Audio,
    Video,
    Application,
    #[doc(hidden)]
    Unknown(String),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    #[default]
    Srtp,
    Sctp,
}

impl Proto {
    pub fn proto_line(&self) -> &str {
        match self {
            Proto::Srtp => "UDP/TLS/RTP/SAVPF",
            Proto::Sctp => "DTLS/SCTP",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Setup {
    #[default]
    ActPass,
    Active,
    Passive,
}

impl fmt::Display for Setup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Setup::ActPass => "actpass",
                Setup::Active => "active",
                Setup::Passive => "passive",
            }
        )
    }
}

impl Setup {
    pub fn setup_line(&self) -> &str {
        match self {
            Setup::ActPass => "actpass",
            Setup::Active => "active",
            Setup::Passive => "passive",
        }
    }

    pub fn compare_to_remote(&self, remote: Setup) -> Option<Setup> {
        use Setup::*;
        match (self, remote) {
            (ActPass, ActPass) => None,
            (ActPass, Active) => Some(Passive),
            (ActPass, Passive) => Some(Active),
            (Active, ActPass) => Some(Active),
            (Active, Active) => None,
            (Active, Passive) => Some(Active),
            (Passive, ActPass) => Some(Passive),
            (Passive, Active) => Some(Passive),
            (Passive, Passive) => None,
        }
    }
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
    Setup(Setup), // active, passive, actpass, holdconn
    Mid(Mid),     // 0, 1, 2
    SctpPort(u16),
    MaxMessageSize(usize),
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
        pt: Pt,                    // 111
        codec: String,             // opus
        clock_rate: u32,           // 48000
        enc_param: Option<String>, // 2 (audio number of channels)
    },
    // rtcp-fb RTCP feedback parameters, repeated
    RtcpFb {
        pt: Pt,        // 111
        value: String, // nack, nack pli, ccm fir...
    },
    // format parameters, seems to be one of these
    Fmtp {
        pt: Pt,                        // 111
        values: Vec<(String, String)>, // minptime=10;useinbandfec=1
    },
    // a=rid:<rid-id> <direction> [pt=<fmt-list>;]<restriction>=<value>
    // a=rid:hi send pt=111,112;max-br=64000;max-height=360
    // https://tools.ietf.org/html/draft-ietf-mmusic-rid-15
    Rid {
        id: RestrictionId,       //
        direction: &'static str, // send or recv
        // No pt means the rid applies to all
        pt: Vec<Pt>, // 111, 112 (rtpmap no)
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
    Rid(RestrictionId),
    Ssrc(u32),
}

impl SimulcastOption {
    pub fn as_stream_id(&self) -> &RestrictionId {
        if let SimulcastOption::Rid(stream_id) = self {
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
        for m in &self.media_lines {
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
            Group { typ, mids } => {
                let mids: Vec<_> = mids.iter().map(|m| m.to_string()).collect();
                write!(f, "a=group:{} {}\r\n", typ, mids.join(" "))?;
            }
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
            Setup(v) => write!(f, "a=setup:{}\r\n", v.setup_line())?,
            Candidate(c) => write!(f, "{}", c)?,
            EndOfCandidates => write!(f, "a=end-of-candidates\r\n")?,
            Unused(v) => write!(f, "a={}\r\n", v)?,
        }
        Ok(())
    }
}

impl fmt::Display for MediaLine {
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
        write!(f, "{}", self.proto_line())
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
            Setup(v) => write!(f, "a=setup:{}\r\n", v.setup_line())?,
            Mid(v) => write!(f, "a=mid:{}\r\n", v)?,
            SctpPort(v) => write!(f, "a=sctp-port:{}", v)?,
            MaxMessageSize(v) => write!(f, "a=max-message-size:{}", v)?,
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
                id,
                direction,
                pt,
                restriction,
            } => {
                write!(f, "a=rid:{} {}", id.0, direction)?;
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
    use rtp::RtpExtensionType;

    use super::*;

    #[test]
    fn write_sdp() {
        let sdp = Sdp { session: Session { id: SessionId(5_058_682_828_002_148_772),
            bw: None, attrs:
            vec![SessionAttribute::Group { typ: "BUNDLE".into(), mids: vec!["0".into()] }, SessionAttribute::Unused("msid-semantic: WMS 5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK".into())] },
            media_lines: vec![
                MediaLine {
                    typ: MediaType::Audio,
                    proto: Proto::Srtp,
                    pts: vec![111.into(), 103.into(), 104.into(), 9.into(), 0.into(), 8.into(), 106.into(), 105.into(), 13.into(), 110.into(), 112.into(), 113.into(), 126.into()],
                    bw: None,
                    attrs: vec![
                        MediaAttribute::Rtcp("9 IN IP4 0.0.0.0".into()),
                        MediaAttribute::IceUfrag("S5hk".into()),
                        MediaAttribute::IcePwd("0zV/Yu3y8aDzbHgqWhnVQhqP".into()),
                        MediaAttribute::IceOptions("trickle".into()),
                        MediaAttribute::Fingerprint(Fingerprint { hash_func: "sha-256".into(), bytes: vec![140, 100, 237, 3, 118, 208, 61, 180, 136, 8, 145, 100, 8, 128, 168, 198, 90, 191, 139, 78, 56, 39, 150, 202, 8, 73, 37, 115, 70, 96, 32, 220] }),
                        MediaAttribute::Setup(Setup::ActPass),
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
                        MediaAttribute::RtpMap { pt: 111.into(), codec: "opus".into(), clock_rate: 48_000, enc_param: Some("2".into()) },
                        MediaAttribute::RtcpFb { pt: 111.into(), value: "transport-cc".into() },
                        MediaAttribute::Fmtp { pt: 111.into(), values: vec![("minptime".into(), "10".into()), ("useinbandfec".into(), "1".into())] },
                        MediaAttribute::RtpMap { pt: 103.into(), codec: "ISAC".into(), clock_rate: 16_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 104.into(), codec: "ISAC".into(), clock_rate: 32_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 9.into(), codec: "G722".into(), clock_rate: 8_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 0.into(), codec: "PCMU".into(), clock_rate: 8_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 8.into(), codec: "PCMA".into(), clock_rate: 8_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 106.into(), codec: "CN".into(), clock_rate: 32_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 105.into(), codec: "CN".into(), clock_rate: 16_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 13.into(), codec: "CN".into(), clock_rate: 8_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 110.into(), codec: "telephone-event".into(), clock_rate: 48_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 112.into(), codec: "telephone-event".into(), clock_rate: 32_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 113.into(), codec: "telephone-event".into(), clock_rate: 16_000, enc_param: None },
                        MediaAttribute::RtpMap { pt: 126.into(), codec: "telephone-event".into(), clock_rate: 8_000, enc_param: None },
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
