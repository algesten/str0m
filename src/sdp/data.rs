#![allow(clippy::single_match)]

use combine::EasyParser;
use std::collections::HashSet;
use std::fmt::{self};
use std::num::ParseFloatError;
use std::ops::Deref;
use std::str::FromStr;

use crate::dtls::Fingerprint;
use crate::ice::{Candidate, IceCreds};
use crate::rtp::{Direction, ExtMap, Mid, Pt, SessionId, Ssrc};

use super::parser::sdp_parser;
use super::SdpError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sdp {
    pub session: Session,
    pub media_lines: Vec<MediaLine>,
}

impl Sdp {
    #[doc(hidden)]
    pub fn parse(input: &str) -> Result<Sdp, SdpError> {
        sdp_parser()
            .easy_parse(input)
            .map(|(sdp, _)| sdp)
            .map_err(|e| SdpError::ParseError(e.to_string()))
    }

    #[doc(hidden)]
    pub fn assert_consistency(&self) -> Result<(), SdpError> {
        match self.do_assert_consistency() {
            None => Ok(()),
            Some(error) => Err(SdpError::Inconsistent(error)),
        }
    }

    #[doc(hidden)]
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.session
            .fingerprint()
            .or_else(|| self.media_lines.iter().find_map(|m| m.fingerprint()))
    }

    #[doc(hidden)]
    pub fn ice_creds(&self) -> Option<IceCreds> {
        self.session
            .ice_creds()
            .or_else(|| self.media_lines.iter().find_map(|m| m.ice_creds()))
    }

    #[doc(hidden)]
    pub fn ice_candidates(&self) -> impl Iterator<Item = &Candidate> {
        let mut candidates: HashSet<&Candidate> = HashSet::new();

        // Session level ice candidates.
        candidates.extend(self.session.ice_candidates());

        // Ice candidates.
        for m in &self.media_lines {
            candidates.extend(m.ice_candidates());
        }

        candidates.into_iter()
    }

    #[doc(hidden)]
    pub fn setup(&self) -> Option<Setup> {
        self.session
            .setup()
            .or_else(|| self.media_lines.iter().find_map(|m| m.setup()))
    }

    fn do_assert_consistency(&self) -> Option<String> {
        let group = self
            .session
            .attrs
            .iter()
            .find(|a| matches!(a, SessionAttribute::Group { .. }));

        if let Some(SessionAttribute::Group { mids, .. }) = group {
            if !mids.len() == self.media_lines.len() {
                return Some(format!(
                    "a=group mid count doesn't match m-line count {} != {}",
                    mids.len(),
                    self.media_lines.len()
                ));
            }
            for (media, mid) in self.media_lines.iter().zip(mids.iter()) {
                media.check_consistent()?;
                let m = media.mid();
                if m != *mid {
                    return Some(format!("Mid order not matching a=group {m} != {mid}"));
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

    pub fn rtp_params(&self) -> Vec<PayloadParams> {
        let rtp_maps: Vec<_> = self
            .attrs
            .iter()
            .filter_map(|a| {
                if let MediaAttribute::RtpMap(c) = a {
                    Some(c)
                } else {
                    None
                }
            })
            .collect();

        let fmtps: Vec<_> = self
            .attrs
            .iter()
            .filter_map(|a| {
                if let MediaAttribute::Fmtp { pt, values } = a {
                    Some((pt, values))
                } else {
                    None
                }
            })
            .collect();

        let fbs: Vec<_> = self
            .attrs
            .iter()
            .filter_map(|a| {
                if let MediaAttribute::RtcpFb { pt, value } = a {
                    Some((pt, value))
                } else {
                    None
                }
            })
            .collect();

        let mut params: Vec<_> = rtp_maps
            .iter()
            .filter(|c| c.codec.is_audio() | c.codec.is_video())
            .map(|c| PayloadParams::new(**c))
            .collect();

        for p in &mut params {
            for (pt, values) in fmtps.iter() {
                // find matching a=fmtp line, if it exists.
                if **pt == p.codec.pt {
                    p.fmtps.set_attributes(values);
                }

                // find resend pt, if there is one.
                for fp in values.iter() {
                    if let FormatParam::Apt(v) = fp {
                        if *v == p.codec.pt {
                            // ensure this is a rtx
                            let is_rtx = rtp_maps
                                .iter()
                                .any(|c| c.pt == **pt && c.codec == Codec::Rtx);
                            if is_rtx {
                                p.resend = Some(**pt);
                            }
                        }
                    }
                }
            }

            // rtcp feedback mechanisms
            for (pt, value) in fbs.iter() {
                if **pt == p.codec.pt {
                    match &value[..] {
                        "goog-remb" => {
                            //
                        }
                        "transport-cc" => {
                            p.fb_transport_cc = true;
                        }
                        "ccm fir" => {
                            p.fb_fir = true;
                        }
                        "nack" => {
                            p.fb_nack = true;
                        }
                        "nack pli" => {
                            p.fb_pli = true;
                        }
                        _ => {
                            //
                        }
                    }
                }
            }
        }

        params
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

        if setup > 1 {
            return Some(format!(
                "Expected 0 or 1 a=setup: line for mid: {}",
                self.mid()
            ));
        }

        let dir_count = self.attrs.iter().filter(|a| is_dir(a)).count();

        if self.proto == Proto::Srtp && dir_count != 1 {
            return Some(format!(
                "Expected exactly one of a=sendrecv, a=sendonly, a=recvonly, a=inactive for mid: {}",
                self.mid()
            ));
        }

        if self.proto == Proto::Srtp && self.pts.is_empty() {
            return Some(format!("Expected at least one PT for mid: {}", self.mid()));
        }

        for m in &self.pts {
            let rtp_count = self
                .attrs
                .iter()
                .filter(|a| {
                    if let MediaAttribute::RtpMap(c) = a {
                        c.pt == *m
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
                ret.push(*e);
            }
        }

        ret
    }

    pub fn simulcast(&self) -> Option<Simulcast> {
        let mut found = None;

        for a in &self.attrs {
            if let MediaAttribute::Simulcast(s) = a {
                found = Some(s.clone());
            }
            if let MediaAttribute::Rid {
                pt, restriction, ..
            } = a
            {
                if !pt.is_empty() {
                    warn!("Not currently supporting PT via a=rid");
                }
                if !restriction.is_empty() {
                    warn!("Not currently supporting restrictions via a=rid");
                }
            }
        }

        if found.is_some() {
            return found;
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

    pub fn ssrc_info(&self) -> Vec<SsrcInfo> {
        let mut v = vec![];

        fn by_ssrc(v: &mut Vec<SsrcInfo>, ssrc: Ssrc) -> &mut SsrcInfo {
            if let Some(pos) = v.iter().position(|i| i.ssrc == ssrc) {
                &mut v[pos]
            } else {
                v.push(SsrcInfo {
                    ssrc,
                    ..Default::default()
                });
                v.last_mut().unwrap()
            }
        }

        for a in &self.attrs {
            match a {
                MediaAttribute::Ssrc { ssrc, attr, value } => {
                    let info = by_ssrc(&mut v, *ssrc);

                    // a=ssrc:2147603131 cname:TbS1Ajv9obq6/63I
                    // a=ssrc:2147603131 msid:- 7a08dda6-518f-4027-b707-410a6d414176
                    match attr.to_lowercase().as_str() {
                        "cname" => info.cname = Some(value.clone()),
                        "msid" => {
                            let mut iter = value.split(' ');

                            fn trim_and_no_minus(s: &str) -> Option<String> {
                                let s = s.trim();

                                if s == "-" {
                                    None
                                } else {
                                    Some(s.into())
                                }
                            }

                            if let Some(stream_id) = iter.next() {
                                info.stream_id = trim_and_no_minus(stream_id);
                            }
                            if let Some(track_id) = iter.next() {
                                info.track_id = trim_and_no_minus(track_id);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        // Match this second to ensure we preserve order of a=ssrc.
        for a in &self.attrs {
            match a {
                MediaAttribute::SsrcGroup { semantics, ssrcs } => {
                    if semantics.to_lowercase() != "fid" {
                        continue;
                    }

                    // a=ssrc-group:FID 659652645 98148385
                    // Should be two SSRC after FID.
                    if ssrcs.len() != 2 {
                        continue;
                    }

                    let info = by_ssrc(&mut v, ssrcs[1]);
                    info.repair = Some(ssrcs[0]);
                }
                _ => {}
            }
        }

        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrcInfo {
    pub ssrc: Ssrc,
    pub repair: Option<Ssrc>,
    pub cname: Option<String>,
    pub stream_id: Option<String>,
    pub track_id: Option<String>,
}

impl Default for SsrcInfo {
    fn default() -> Self {
        Self {
            ssrc: 0.into(),
            repair: None,
            cname: None,
            stream_id: None,
            track_id: None,
        }
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

impl MediaType {
    pub fn is_media(&self) -> bool {
        matches!(self, MediaType::Audio | MediaType::Video)
    }

    pub fn is_channel(&self) -> bool {
        matches!(self, MediaType::Application)
    }
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
            Proto::Sctp => "UDP/DTLS/SCTP",
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

    pub fn invert(&self) -> Setup {
        match self {
            Setup::ActPass => Setup::ActPass,
            Setup::Active => Setup::Passive,
            Setup::Passive => Setup::Active,
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
    Msid(Msid),
    RtcpMux,     //
    RtcpMuxOnly, // only in offer, answer with a=rtcp-mux
    // reduced size rtcp. remove this if not supported.
    RtcpRsize,
    Candidate(Candidate),
    EndOfCandidates,
    RtpMap(CodecSpec),
    // rtcp-fb RTCP feedback parameters, repeated
    RtcpFb {
        pt: Pt,        // 111
        value: String, // nack, nack pli, ccm fir...
    },
    // format parameters, seems to be one of these
    Fmtp {
        pt: Pt,                   // 111
        values: Vec<FormatParam>, // minptime=10;useinbandfec=1
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
        ssrcs: Vec<Ssrc>,  // <normal stream> <repair stream>
    },
    Ssrc {
        ssrc: Ssrc, // synchronization source id
        attr: String,
        value: String,
    },
    Unused(String),
}

impl MediaAttribute {
    pub fn is_direction(&self) -> bool {
        use MediaAttribute::*;
        matches!(self, RecvOnly | SendRecv | SendOnly | Inactive)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodecSpec {
    pub pt: Pt,
    pub codec: Codec,
    pub clock_rate: u32,
    pub channels: Option<u8>,
}

/// Codec specific format parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FormatParams {
    /// Opus specific parameter.
    ///
    /// The minimum duration of media represented by a packet.
    pub min_p_time: Option<u8>,

    /// Opus specific parameter.
    ///
    /// Specifies that the decoder can do Opus in-band FEC
    pub use_inband_fec: Option<bool>,

    /// Whether h264 sending media encoded at a different level in the offerer-to-answerer
    /// direction than the level in the answerer-to-offerer direction, is allowed.
    pub level_asymmetry_allowed: Option<bool>,

    /// What h264 packetization mode is used.
    ///
    /// * 0 - single nal.
    /// * 1 - STAP-A, FU-A is allowed. Non-interleaved.
    pub packetization_mode: Option<u8>,

    /// H264 profile level.
    ///
    /// * 42 00 1f - 4200=baseline (B)              1f=level 3.1
    /// * 42 e0 1f - 42e0=constrained baseline (CB) 1f=level 3.1
    /// * 4d 00 1f - 4d00=main (M)                  1f=level 3.1
    /// * 64 00 1f - 6400=high (H)                  1f=level 3.1
    pub profile_level_id: Option<u32>,

    /// VP9 profile id.
    pub profile_id: Option<u32>,
}

impl FormatParams {
    fn set_attributes(&mut self, values: &[FormatParam]) {
        use FormatParam::*;
        for v in values {
            match v {
                MinPTime(v) => self.min_p_time = Some(*v),
                UseInbandFec(v) => self.use_inband_fec = Some(*v),
                LevelAsymmetryAllowed(v) => self.level_asymmetry_allowed = Some(*v),
                PacketizationMode(v) => self.packetization_mode = Some(*v),
                ProfileLevelId(v) => self.profile_level_id = Some(*v),
                ProfileId(v) => self.profile_id = Some(*v),
                Apt(_) => {}
                Unknown => {}
            }
        }
    }

    fn to_format_param(self) -> Vec<FormatParam> {
        use FormatParam::*;
        let mut r = Vec::with_capacity(5);

        if let Some(v) = self.min_p_time {
            r.push(MinPTime(v));
        }
        if let Some(v) = self.use_inband_fec {
            r.push(UseInbandFec(v));
        }
        if let Some(v) = self.level_asymmetry_allowed {
            r.push(LevelAsymmetryAllowed(v));
        }
        if let Some(v) = self.packetization_mode {
            r.push(PacketizationMode(v));
        }
        if let Some(v) = self.profile_level_id {
            r.push(ProfileLevelId(v));
        }
        if let Some(v) = self.profile_id {
            r.push(ProfileId(v));
        }

        r
    }
}

impl fmt::Display for FormatParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self
            .to_format_param()
            .into_iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(";");
        write!(f, "{s}")
    }
}

/// Known codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Codec {
    Opus,
    H264,
    // TODO show this when we support h265.
    #[doc(hidden)]
    H265,
    Vp8,
    Vp9,
    // TODO show this when we support Av1.
    #[doc(hidden)]
    Av1,
    /// Technically not a codec, but used in places where codecs go
    /// in `a=rtpmap` lines.
    #[doc(hidden)]
    Rtx,
    #[doc(hidden)]
    Unknown,
}

impl Codec {
    /// Tells if codec is audio.
    pub fn is_audio(&self) -> bool {
        use Codec::*;
        matches!(self, Opus)
    }

    /// Tells if codec is video.
    pub fn is_video(&self) -> bool {
        use Codec::*;
        matches!(self, H264 | Vp8 | Vp9 | Av1)
    }
}

impl<'a> From<&'a str> for Codec {
    fn from(v: &'a str) -> Self {
        let lc = v.to_ascii_lowercase();
        match &lc[..] {
            "opus" => Codec::Opus,
            "h264" => Codec::H264,
            "h265" => Codec::H265,
            "vp8" => Codec::Vp8,
            "vp9" => Codec::Vp9,
            "av1" => Codec::Av1,
            "rtx" => Codec::Rtx, // resends
            _ => Codec::Unknown,
        }
    }
}

impl fmt::Display for Codec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Codec::Opus => write!(f, "opus"),
            Codec::H264 => write!(f, "H264"),
            Codec::H265 => write!(f, "H265"),
            Codec::Vp8 => write!(f, "VP8"),
            Codec::Vp9 => write!(f, "VP9"),
            Codec::Av1 => write!(f, "AV1"),
            Codec::Rtx => write!(f, "rtx"),
            Codec::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadParams {
    pub codec: CodecSpec,
    pub fmtps: FormatParams,
    pub resend: Option<Pt>,
    pub fb_transport_cc: bool,
    pub fb_fir: bool,
    pub fb_nack: bool,
    pub fb_pli: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatParam {
    /// The minimum duration of media represented by a packet.
    ///
    /// Default 3. Max 120.
    MinPTime(u8),

    /// Specifies that the decoder can do Opus in-band FEC
    UseInbandFec(bool),

    /// Whether h264 sending media encoded at a different level in the offerer-to-answerer
    /// direction than the level in the answerer-to-offerer direction, is allowed.
    LevelAsymmetryAllowed(bool),

    /// What h264 packetization mode is used.
    ///
    /// * 0 - single nal.
    /// * 1 - STAP-A, FU-A is allowed. Non-interleaved.
    PacketizationMode(u8),

    /// H264 profile level.
    ///
    /// * 42 00 1f - 4200=baseline (B)              1f=level 3.1
    /// * 42 e0 1f - 42e0=constrained baseline (CB) 1f=level 3.1
    /// * 4d 00 1f - 4d00=main (M)                  1f=level 3.1
    /// * 64 00 1f - 6400=high (H)                  1f=level 3.1
    ProfileLevelId(u32),

    /// VP9 profile id
    ProfileId(u32),

    /// RTX (resend) codecs, which PT it concerns.
    Apt(Pt),

    /// Unrecognized fmtp.
    Unknown,
}

impl FormatParam {
    pub fn parse(k: &str, v: &str) -> Self {
        use FormatParam::*;
        match k {
            "minptime" => {
                if let Ok(v) = v.parse() {
                    MinPTime(v)
                } else {
                    trace!("Failed to parse: {}", k);
                    Unknown
                }
            }
            "useinbandfec" => UseInbandFec(v == "1"),
            "level-asymmetry-allowed" => LevelAsymmetryAllowed(v == "1"),
            "packetization-mode" => {
                if let Ok(v) = v.parse() {
                    PacketizationMode(v)
                } else {
                    trace!("Failed to parse: {}", k);
                    Unknown
                }
            }
            "profile-level-id" => {
                if let Ok(v) = u32::from_str_radix(v, 16).or_else(|_| v.parse()) {
                    ProfileLevelId(v)
                } else {
                    trace!("Failed to parse: {}", k);
                    Unknown
                }
            }
            "profile-id" => {
                if let Ok(v) = v.parse() {
                    ProfileId(v)
                } else {
                    trace!("Failed to parse: {}", k);
                    Unknown
                }
            }
            "apt" => {
                if let Ok(v) = v.parse::<u8>() {
                    Apt(v.into())
                } else {
                    trace!("Failed to parse: {}", k);
                    Unknown
                }
            }
            _ => Unknown,
        }
    }
}

impl fmt::Display for FormatParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FormatParam::*;
        match self {
            MinPTime(v) => write!(f, "minptime={v}"),
            UseInbandFec(v) => write!(f, "useinbandfec={}", i32::from(*v)),
            LevelAsymmetryAllowed(v) => {
                write!(f, "level-asymmetry-allowed={}", i32::from(*v))
            }
            PacketizationMode(v) => write!(f, "packetization-mode={}", *v),
            ProfileLevelId(v) => write!(f, "profile-level-id={:06x}", *v),
            ProfileId(v) => write!(f, "profile-id={}", *v),
            Apt(v) => write!(f, "apt={v}"),
            Unknown => Ok(()),
        }
    }
}

impl PayloadParams {
    fn new(codec: CodecSpec) -> Self {
        PayloadParams {
            codec,
            fmtps: FormatParams::default(),
            resend: None,
            fb_transport_cc: false,
            fb_fir: false,
            fb_nack: false,
            fb_pli: false,
        }
    }

    pub fn as_media_attrs(&self, attrs: &mut Vec<MediaAttribute>) {
        attrs.push(MediaAttribute::RtpMap(self.codec));

        if self.fb_transport_cc {
            attrs.push(MediaAttribute::RtcpFb {
                pt: self.codec.pt,
                value: "transport-cc".into(),
            });
        }
        if self.fb_fir {
            attrs.push(MediaAttribute::RtcpFb {
                pt: self.codec.pt,
                value: "ccm fir".into(),
            });
        }
        if self.fb_nack {
            attrs.push(MediaAttribute::RtcpFb {
                pt: self.codec.pt,
                value: "nack".into(),
            });
        }
        if self.fb_pli {
            attrs.push(MediaAttribute::RtcpFb {
                pt: self.codec.pt,
                value: "nack pli".into(),
            });
        }

        let fmtps = self.fmtps.to_format_param();
        if !fmtps.is_empty() {
            attrs.push(MediaAttribute::Fmtp {
                pt: self.codec.pt,
                values: fmtps,
            });
        }

        if let Some(pt) = self.resend {
            attrs.push(MediaAttribute::RtpMap(CodecSpec {
                pt,
                codec: Codec::Rtx,
                clock_rate: self.codec.clock_rate,
                channels: None,
            }));
            attrs.push(MediaAttribute::Fmtp {
                pt,
                values: vec![FormatParam::Apt(self.codec.pt)],
            });
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Simulcast {
    pub send: SimulcastGroups,
    pub recv: SimulcastGroups,
    /// If this is created synthetically for a munged SDP.
    pub is_munged: bool,
}

impl Simulcast {
    pub fn invert(self) -> Self {
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

impl Deref for SimulcastGroups {
    type Target = [SimulcastGroup];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulcastGroup(pub Vec<SimulcastOption>);

impl Deref for SimulcastGroup {
    type Target = [SimulcastOption];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimulcastOption {
    Rid(RestrictionId),
    Ssrc(Ssrc),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msid {
    pub stream_id: String,
    pub track_id: String,
}

impl fmt::Display for SimulcastGroups {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, a) in self.0.iter().enumerate() {
            if idx + 1 == self.0.len() {
                write!(f, "{a}")?;
            } else {
                write!(f, "{a},")?;
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
            write!(f, "{m}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v=0\r\n")?;
        write!(f, "o=- {} 2 IN IP4 0.0.0.0\r\n", self.id)?;
        write!(f, "s=-\r\n")?;
        if let Some(bw) = &self.bw {
            write!(f, "b={}:{}\r\n", bw.typ, bw.val)?;
        }
        write!(f, "t=0 0\r\n")?;
        for a in &self.attrs {
            write!(f, "{a}")?;
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
            IceUfrag(v) => write!(f, "a=ice-ufrag:{v}\r\n")?,
            IcePwd(v) => write!(f, "a=ice-pwd:{v}\r\n")?,
            IceOptions(v) => write!(f, "a=ice-options:{v}\r\n")?,
            Fingerprint(v) => {
                write!(
                    f,
                    "a=fingerprint:{} {}\r\n",
                    v.hash_func,
                    FingerprintFmt(&v.bytes)
                )?;
            }
            Setup(v) => write!(f, "a=setup:{}\r\n", v.setup_line())?,
            Candidate(c) => write!(f, "{c}")?,
            EndOfCandidates => write!(f, "a=end-of-candidates\r\n")?,
            Unused(v) => write!(f, "a={v}\r\n")?,
        }
        Ok(())
    }
}

impl fmt::Display for MediaLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m={} 9 {} ", self.typ, self.proto,)?;
        let len = self.pts.len();
        if self.typ.is_channel() {
            write!(f, "webrtc-datachannel\r\n")?;
        } else {
            for (idx, m) in self.pts.iter().enumerate() {
                if idx + 1 < len {
                    write!(f, "{m} ")?;
                } else {
                    write!(f, "{m}")?;
                }
            }
            write!(f, "\r\n")?;
        }
        write!(f, "c=IN IP4 0.0.0.0\r\n")?;
        if let Some(bw) = &self.bw {
            write!(f, "b={}:{}\r\n", bw.typ, bw.val)?;
        }
        for a in &self.attrs {
            write!(f, "{a}")?;
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
            MediaType::Unknown(v) => write!(f, "{v}"),
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
            Rtcp(v) => write!(f, "a=rtcp:{v}\r\n")?,
            IceUfrag(v) => write!(f, "a=ice-ufrag:{v}\r\n")?,
            IcePwd(v) => write!(f, "a=ice-pwd:{v}\r\n")?,
            IceOptions(v) => write!(f, "a=ice-options:{v}\r\n")?,
            Fingerprint(v) => {
                write!(
                    f,
                    "a=fingerprint:{} {}\r\n",
                    v.hash_func,
                    FingerprintFmt(&v.bytes)
                )?;
            }
            Setup(v) => write!(f, "a=setup:{}\r\n", v.setup_line())?,
            Mid(v) => write!(f, "a=mid:{v}\r\n")?,
            SctpPort(v) => write!(f, "a=sctp-port:{v}\r\n")?,
            MaxMessageSize(v) => write!(f, "a=max-message-size:{v}\r\n")?,
            ExtMap(e) => {
                if !e.ext.is_serialized() {
                    return Ok(());
                }
                write!(f, "a=extmap:{}", e.id)?;
                if let Some(d) = &e.direction {
                    write!(f, "/{d}")?;
                }
                write!(f, " {}", e.ext.as_uri())?;
                // if let Some(e) = &e.ext {
                //     write!(f, " {}", e)?;
                // }
                write!(f, "\r\n")?;
            }
            RecvOnly => write!(f, "a=recvonly\r\n")?,
            SendRecv => write!(f, "a=sendrecv\r\n")?,
            SendOnly => write!(f, "a=sendonly\r\n")?,
            Inactive => write!(f, "a=inactive\r\n")?,
            // a=msid:5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK f78dde68-7055-4e20-bb37-433803dd1ed1
            // a=msid:- 78dde68-7055-4e20-bb37-433803dd1ed1
            Msid(v) => write!(f, "a=msid:{} {}\r\n", v.stream_id, v.track_id)?,
            RtcpMux => write!(f, "a=rtcp-mux\r\n")?,
            RtcpMuxOnly => write!(f, "a=rtcp-mux-only\r\n")?,
            RtcpRsize => write!(f, "a=rtcp-rsize\r\n")?,
            Candidate(c) => write!(f, "{c}")?,
            EndOfCandidates => write!(f, "a=end-of-candidates\r\n")?,
            RtpMap(c) => {
                write!(f, "a=rtpmap:{} {}/{}", c.pt, c.codec, c.clock_rate)?;
                if let Some(e) = c.channels {
                    write!(f, "/{e}")?;
                }
                write!(f, "\r\n")?;
            }
            RtcpFb { pt, value } => write!(f, "a=rtcp-fb:{pt} {value}\r\n")?,
            Fmtp { pt, values } => {
                write!(f, "a=fmtp:{pt} ")?;
                for (idx, v) in values.iter().enumerate() {
                    if idx + 1 < values.len() {
                        write!(f, "{v};")?;
                    } else {
                        write!(f, "{v}\r\n")?;
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
                        write!(f, "{p}")?;
                    } else {
                        write!(f, "{p},")?;
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
                        write!(f, "{k}={v}")?;
                    } else {
                        write!(f, "{k}={v};")?;
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
                    // don't write
                    return Ok(());
                }
                write!(f, "a=simulcast:")?;
                if !send.0.is_empty() {
                    write!(f, "send {send}")?;
                }
                if !recv.0.is_empty() {
                    if !send.0.is_empty() {
                        write!(f, " ")?;
                    }
                    write!(f, "recv {recv}")?;
                }
                write!(f, "\r\n")?;
            }
            SsrcGroup { semantics, ssrcs } => {
                write!(f, "a=ssrc-group:{semantics} ")?;
                for (idx, ssrc) in ssrcs.iter().enumerate() {
                    if idx + 1 < ssrcs.len() {
                        write!(f, "{} ", **ssrc)?;
                    } else {
                        write!(f, "{}\r\n", **ssrc)?;
                    }
                }
            }
            Ssrc { ssrc, attr, value } => {
                write!(f, "a=ssrc:{} {}:{}\r\n", **ssrc, attr, value)?;
            }
            Unused(v) => write!(f, "a={v}\r\n")?,
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
                write!(f, "{b:02X}:")?;
            } else {
                write!(f, "{b:02X}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::rtp::Extension;

    use super::*;

    #[test]
    fn fmtp_param_to_string() {
        let f = FormatParams {
            min_p_time: Some(10),
            use_inband_fec: Some(true),
            ..Default::default()
        };
        assert_eq!(f.to_string(), "minptime=10;useinbandfec=1");
    }

    #[test]
    fn parse_error() {
        let input = "v=0\r\n\
        o=mozilla...THIS_IS_SDPARTA-99.0 7710052215259647220 2 IN IP4 0.0.0.0\r\n\
        s=-\r\n\
        t=0 0\r\n\
        a=fingerprint:sha-256 A6:64:23:37:94:7E:4B:40:F6:62:86:8C:DD:09:D5:08:7E:D4:0E:68:58:93:45:EC:99:F2:91:F7:19:72:E7:BB\r\n\
        a=group:BUNDLE 0 hxI i1X mxk B3D kNI nbB xIZ bKm Hkn\r\n\
        a=ice-options:trickle\r\n\
        a=msid-semantic:WMS *\r\n\
        m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n\
        c=IN IP4 0.0.0.0\r\n\
        a=setup:actpass\r\n\
        a=mid:1\r\n\
        a=rtpmap:0 PCMU/8000\r\n\
        ";

        let sdp = Sdp::parse(input);

        match sdp {
            Err(SdpError::ParseError(out)) => {
                assert!(out.starts_with(&"Parse error at ".to_string()));
                assert!(out.contains(&"Expected exactly one of a=sendrecv, a=sendonly, a=recvonly, a=inactive for mid: 1".to_string()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn write_sdp() {
        let sdp = Sdp { session: Session { id: 5_058_682_828_002_148_772.into(),
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
                        MediaAttribute::ExtMap(ExtMap { id: 1, direction: None, ext: Extension::AudioLevel }),
                        MediaAttribute::ExtMap(ExtMap { id: 2, direction: None, ext: Extension::AbsoluteSendTime }),
                        MediaAttribute::ExtMap(ExtMap { id: 3, direction: None, ext: Extension::TransportSequenceNumber }),
                        MediaAttribute::ExtMap(ExtMap { id: 4, direction: None, ext: Extension::RtpMid }),
                        MediaAttribute::ExtMap(ExtMap { id: 5, direction: None, ext: Extension::RtpStreamId }),
                        MediaAttribute::ExtMap(ExtMap { id: 6, direction: None, ext: Extension::RepairedRtpStreamId }),
                        MediaAttribute::SendRecv,
                        MediaAttribute::Msid(Msid { stream_id: "5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK".into(), track_id: "f78dde68-7055-4e20-bb37-433803dd1ed1".into() }),
                        MediaAttribute::RtcpMux,
                        MediaAttribute::RtpMap( CodecSpec { pt: 111.into(), codec: "opus".into(), clock_rate: 48_000, channels: Some(2) }),
                        MediaAttribute::RtcpFb { pt: 111.into(), value: "transport-cc".into() },
                        MediaAttribute::Fmtp { pt: 111.into(), values: vec![FormatParam::MinPTime(10), FormatParam::UseInbandFec(true)] },
                        MediaAttribute::Ssrc { ssrc: 3_948_621_874.into(), attr: "cname".into(), value: "xeXs3aE9AOBn00yJ".into() },
                        MediaAttribute::Ssrc { ssrc: 3_948_621_874.into(), attr: "msid".into(), value: "5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK f78dde68-7055-4e20-bb37-433803dd1ed1".into() },
                        MediaAttribute::Ssrc { ssrc: 3_948_621_874.into(), attr: "mslabel".into(), value: "5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK".into() },
                        MediaAttribute::Ssrc { ssrc: 3_948_621_874.into(), attr: "label".into(), value: "f78dde68-7055-4e20-bb37-433803dd1ed1".into() }] }] };
        assert_eq!(&format!("{sdp}"), "v=0\r\n\
            o=- 5058682828002148772 2 IN IP4 0.0.0.0\r\n\
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
            a=ssrc:3948621874 cname:xeXs3aE9AOBn00yJ\r\n\
            a=ssrc:3948621874 msid:5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK f78dde68-7055-4e20-bb37-433803dd1ed1\r\n\
            a=ssrc:3948621874 mslabel:5UUdwiuY7OML2EkQtF38pJtNP5v7In1LhjEK\r\n\
            a=ssrc:3948621874 label:f78dde68-7055-4e20-bb37-433803dd1ed1\r\n\
            ");
    }
}
