use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ops::RangeInclusive;

use crate::packet::H264ProfileLevel;
use crate::rtp_::Pt;

use super::codec::{Codec, CodecSpec};

/// Preferred ranges for dynamic payload type allocation.
pub(crate) const PREFERED_RANGES: &[RangeInclusive<usize>] = &[
    // Payload identifiers 96–127 are used for payloads defined dynamically during a session.
    96..=127,
    // "unassigned" ranged. note that RTCP packet type 207 (XR, Extended Reports) would be
    // indistinguishable from RTP payload types 79 with the marker bit set
    80..=95,
    77..=78,
    // reserved because RTCP packet types 200–204 would otherwise be indistinguishable
    // from RTP payload types 72–76
    // 72..77,
    // lol range.
    35..=71,
];

pub(crate) trait Claimed {
    fn assert_claim_once(&mut self, pt: Pt);
    fn is_claimed(&self, pt: Pt) -> bool;
    fn find_unclaimed(
        &self,
        ranges: &[RangeInclusive<usize>],
        unlocked: &HashSet<Pt>,
    ) -> Option<Pt>;
}

impl Claimed for [bool; 128] {
    fn assert_claim_once(&mut self, pt: Pt) {
        let idx = *pt as usize;
        assert!(!self[idx], "Pt locked multiple times: {}", pt);
        self[idx] = true;
    }
    fn is_claimed(&self, pt: Pt) -> bool {
        let idx = *pt as usize;
        self[idx]
    }
    fn find_unclaimed(
        &self,
        ranges: &[RangeInclusive<usize>],
        unlocked: &HashSet<Pt>,
    ) -> Option<Pt> {
        for range in ranges {
            for i in range.clone() {
                if !self[i] && !unlocked.contains(&(i as u8).into()) {
                    let pt: Pt = (i as u8).into();
                    return Some(pt);
                }
            }
        }

        // Failed to find unclaimed PT.
        None
    }
}

/// Group of parameters for a payload type (PT).
///
/// In the SDP a payload type has a number of associated parameters. See example below:
///
/// ```text
/// a=rtpmap:96 H264/90000
/// a=rtcp-fb:96 goog-remb
/// a=rtcp-fb:96 transport-cc
/// a=rtcp-fb:96 ccm fir
/// a=rtcp-fb:96 nack
/// a=rtcp-fb:96 nack pli
/// a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f
/// ```
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PayloadParams {
    /// The payload type that groups these parameters.
    pub(crate) pt: Pt,

    /// Whether these parameters are repairing some other set of parameters.
    /// This is used to, via PT, separate RTX resend streams from the main stream.
    pub(crate) resend: Option<Pt>,

    /// The codec with settings for this group of parameters.
    pub(crate) spec: CodecSpec,

    /// Whether the payload use the TWCC feedback mechanic.
    pub(crate) fb_transport_cc: bool,

    /// Whether the payload uses NACK to request resends.
    pub(crate) fb_nack: bool,

    /// Whether the payload uses the PLI (Picture Loss Indication) mechanic.
    pub(crate) fb_pli: bool,

    /// Whether the payload uses the FIR (Full Intra Request) mechanic.
    pub(crate) fb_fir: bool,

    /// Whether the payload uses the REMB (Receiver Estimated Maximum Bitrate) mechanic.
    pub(crate) fb_remb: bool,

    /// Whether the payload is locked by negotiation or can still be debated.
    ///
    /// If we make an OFFER or ANSWER and the direction is sendrecv/recvonly, the parameters are locked
    /// can't be further changed. If we make an OFFER for a sendonly, the parameters are only proposed
    /// and don't lock.
    pub(crate) locked: bool,
}

// we don't want to compare "locked"
impl PartialEq for PayloadParams {
    fn eq(&self, other: &Self) -> bool {
        self.pt == other.pt
            && self.resend == other.resend
            && self.spec == other.spec
            && self.fb_transport_cc == other.fb_transport_cc
            && self.fb_nack == other.fb_nack
            && self.fb_pli == other.fb_pli
            && self.fb_fir == other.fb_fir
            && self.fb_remb == other.fb_remb
    }
}

impl Eq for PayloadParams {}

impl PayloadParams {
    /// Creates new payload params.
    ///
    /// * `pt` is the payload type RTP mapping in the session.
    /// * `resend` is the payload type used for (RTX) resend channel.
    /// * `spec` configures details about the codec.
    pub fn new(pt: Pt, resend: Option<Pt>, spec: CodecSpec) -> Self {
        let is_video = spec.codec.is_video();

        PayloadParams {
            pt,
            resend,

            spec,

            // Both audio and video use TWCC
            fb_transport_cc: true,

            // Only true for video.
            fb_fir: is_video,
            fb_nack: is_video,
            fb_pli: is_video,
            fb_remb: is_video,

            locked: false,
        }
    }

    /// The payload type that groups these parameters.
    pub fn pt(&self) -> Pt {
        self.pt
    }

    /// Whether these parameters are repairing some other set of parameters.
    /// This is used to, via PT, separate RTX resend streams from the main stream.
    pub fn resend(&self) -> Option<Pt> {
        self.resend
    }

    /// The codec with settings for this group of parameters.
    pub fn spec(&self) -> CodecSpec {
        self.spec
    }

    /// Sets whether the payload use the TWCC feedback mechanic.
    pub fn set_fb_transport_cc(&mut self, fb_transport_cc: bool) {
        self.fb_transport_cc = fb_transport_cc
    }

    /// Whether the payload use the TWCC feedback mechanic.
    pub fn fb_transport_cc(&self) -> bool {
        self.fb_transport_cc
    }

    /// Sets whether the payload uses NACK to request resends.
    pub fn set_fb_nack(&mut self, fb_nack: bool) {
        self.fb_nack = fb_nack
    }

    /// Whether the payload uses NACK to request resends.
    pub fn fb_nack(&self) -> bool {
        self.fb_nack
    }

    /// Set whether the payload uses the PLI (Picture Loss Indication) mechanic.
    pub fn set_fb_pli(&mut self, fb_pli: bool) {
        self.fb_pli = fb_pli
    }

    /// Whether the payload uses the PLI (Picture Loss Indication) mechanic.
    pub fn fb_pli(&self) -> bool {
        self.fb_pli
    }

    /// Set whether the payload uses the FIR (Full Intra Request) mechanic.
    pub fn set_fb_fir(&mut self, fb_fir: bool) {
        self.fb_fir = fb_fir
    }

    /// Whether the payload uses the FIR (Full Intra Request) mechanic.
    pub fn fb_fir(&self) -> bool {
        self.fb_fir
    }

    /// Set whether the payload uses the REMB (Receiver Estimated Maximum Bitrate) mechanic.
    pub fn set_fb_remb(&mut self, fb_remb: bool) {
        self.fb_remb = fb_remb
    }

    /// Whether the payload uses the REMB (Receiver Estimated Maximum Bitrate) mechanic.
    pub fn fb_remb(&self) -> bool {
        self.fb_remb
    }

    pub(crate) fn match_score(&self, o: &PayloadParams) -> Option<usize> {
        // we don't want to compare PT
        let c0 = self.spec;
        let c1 = o.spec;

        if c0 == c1 {
            // Exact match
            return Some(100);
        }

        // Attempt fuzzy matching, since we don't have an exact match
        if c0.codec != c1.codec || (c0.codec == Codec::Unknown && c1.codec == Codec::Unknown) {
            // Codecs must match
            return None;
        }

        if c0.clock_rate != c1.clock_rate {
            // Clock rates must match
            return None;
        }

        if c0.channels != c1.channels {
            // Channels must match
            return None;
        }

        if c0.codec.is_audio() && c0.codec == Codec::Opus {
            return Some(Self::match_opus_score(c0, c1));
        }

        if c0.codec == Codec::H264 {
            return Self::match_h264_score(c0, c1);
        }

        if c0.codec == Codec::Vp9 {
            return Self::match_vp9_score(c0, c1);
        }

        if c0.codec == Codec::Av1 {
            return Self::match_av1_score(c0, c1);
        }

        // TODO: Fuzzy matching for any other audio codecs
        // TODO: Fuzzy matching for video

        None
    }

    fn match_opus_score(c0: CodecSpec, c1: CodecSpec) -> usize {
        let mut score: usize = 100;

        // If neither value is specified both sides should assume the default value, 3.
        let either_p_time_specified =
            c0.format.min_p_time.is_some() || c1.format.min_p_time.is_some();
        if either_p_time_specified && c0.format.min_p_time != c1.format.min_p_time {
            score = score.saturating_sub(1);
        }

        // If neither value is specified both sides should assume FEC is not used as this is
        // the default.
        let either_fec_specified =
            c0.format.use_inband_fec.is_some() || c1.format.use_inband_fec.is_some();

        if either_fec_specified && c0.format.use_inband_fec != c1.format.use_inband_fec {
            score = score.saturating_sub(2);
        }

        // If neither value is specified both sides should assume DTX is not used as this is
        // the default.
        let either_dtx_specified = c0.format.use_dtx.is_some() || c1.format.use_dtx.is_some();
        if either_dtx_specified && c0.format.use_dtx != c1.format.use_dtx {
            score = score.saturating_sub(4);
        }

        score
    }

    fn match_vp9_score(c0: CodecSpec, c1: CodecSpec) -> Option<usize> {
        // Default profile_id is 0. https://datatracker.ietf.org/doc/html/draft-ietf-payload-vp9-16#section-6
        let c0_profile_id = c0.format.profile_id.unwrap_or(0);
        let c1_profile_id = c1.format.profile_id.unwrap_or(0);

        if c0_profile_id != c1_profile_id {
            return None;
        }

        Some(100)
    }

    fn match_av1_score(c0: CodecSpec, c1: CodecSpec) -> Option<usize> {
        // TODO: consider media direction for a proper less or equal matching
        // The AV1 stream sent by either the offerer or the answerer MUST be
        // encoded with a profile, level and tier, lesser or equal to the values
        // of the level-idx, profile and tier declared in the SDP by the receiving
        // agent.
        // https://aomediacodec.github.io/av1-rtp-spec/#723-usage-with-the-sdp-offeranswer-model

        // Default values: profile = 0, level-idx = 5, tier = 0
        // https://aomediacodec.github.io/av1-rtp-spec/#72-sdp-parameters
        let c0_profile = c0.format.profile.unwrap_or(0);
        let c1_profile = c1.format.profile.unwrap_or(0);
        if c0_profile != c1_profile {
            return None;
        }

        let c0_level_idx = c0.format.level_idx.unwrap_or(5);
        let c1_level_idx = c1.format.level_idx.unwrap_or(5);
        if c0_level_idx != c1_level_idx {
            return None;
        }

        let c0_tier = c0.format.tier.unwrap_or(0);
        let c1_tier = c1.format.tier.unwrap_or(0);
        if c0_tier != c1_tier {
            return None;
        }

        Some(100)
    }

    pub(crate) fn match_h264_score(c0: CodecSpec, c1: CodecSpec) -> Option<usize> {
        // Default packetization mode is 0. https://www.rfc-editor.org/rfc/rfc6184#section-6.2
        let c0_packetization_mode = c0.format.packetization_mode.unwrap_or(0);
        let c1_packetization_mode = c1.format.packetization_mode.unwrap_or(0);

        if c0_packetization_mode != c1_packetization_mode {
            return None;
        }

        let c0_profile_level = c0
            .format
            .profile_level_id
            .map(|l| l.try_into().ok())
            .unwrap_or(Some(H264ProfileLevel::FALLBACK))?;
        let c1_profile_level = c1
            .format
            .profile_level_id
            .map(|l| l.try_into().ok())
            .unwrap_or(Some(H264ProfileLevel::FALLBACK))?;

        if c0_profile_level != c1_profile_level {
            return None;
        }

        Some(100)
    }

    pub(crate) fn update_param(
        &mut self,
        remote_pts: &[PayloadParams],
        claimed: &mut [bool; 128],
        local_is_controlling: bool,
        unlocked: &mut HashSet<Pt>,
    ) {
        let Some((first, _)) = remote_pts
            .iter()
            .filter_map(|p| self.match_score(p).map(|s| (p, s)))
            .max_by_key(|(_, s)| *s)
        else {
            return;
        };

        let mut remote_pt = first.pt;
        let mut remote_rtx = first.resend;

        if self.locked {
            // This can happen if the incoming PTs are suggestions (send-direction) rather than demanded
            // (receive-direction). We only want to warn if we get receive direction changes.
            if local_is_controlling {
                return;
            }
            // Just verify it's still the same. We should validate this in apply_offer/answer instead
            // of ever seeing this error message.
            if self.pt != remote_pt {
                warn!("Ignore remote PT change {} => {}", self.pt, remote_pt);
            }

            if self.resend != remote_rtx {
                warn!(
                    "Ignore remote PT RTX change {:?} => {:?}",
                    self.resend, remote_rtx
                );
            }
        } else {
            // Before locking, check if the remote PT conflicts with an already locked PT.
            // If we're receiving, we control what PTs to use,
            // so we can remap the conflicting PT.
            if local_is_controlling && claimed.is_claimed(remote_pt) {
                // Try to use the codec's default PT first, fall back to any free PT
                let new_pt = self
                    .spec
                    .codec
                    .default_pt()
                    .filter(|pt| !claimed.is_claimed(*pt))
                    .or_else(|| claimed.find_unclaimed(PREFERED_RANGES, unlocked));

                if let Some(new_pt) = new_pt {
                    debug!(
                        "Remapped conflicting PT {} => {} for codec {:?}",
                        remote_pt, new_pt, self.spec.codec
                    );
                    remote_pt = new_pt;
                    unlocked.remove(&new_pt);
                } else {
                    panic!("Exhausted all PT ranges, inconsistent PayloadParam state");
                }
            }

            // Lock down the PT
            self.pt = remote_pt;
            claimed.assert_claim_once(remote_pt);

            // Check if RTX PT also conflicts
            if local_is_controlling {
                if let Some(rtx) = remote_rtx {
                    if claimed.is_claimed(rtx) {
                        if let Some(new_rtx) = claimed.find_unclaimed(PREFERED_RANGES, unlocked) {
                            debug!("Remapped conflicting RTX PT {:?} => {}", rtx, new_rtx);
                            remote_rtx = Some(new_rtx);
                            unlocked.remove(&new_rtx);
                        } else {
                            panic!("Exhausted all PT ranges, inconsistent PayloadParam state");
                        }
                    }
                }
            }

            // Lock down the RTX PT
            self.resend = remote_rtx;
            if let Some(rtx) = remote_rtx {
                claimed.assert_claim_once(rtx);
            }

            // This is now locked.
            self.locked = true;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::rtp_::Frequency;

    use super::*;
    use crate::format::{CodecSpec, FormatParams};

    fn h264_codec_spec(
        level_asymmetry_allowed: Option<bool>,
        packetization_mode: Option<u8>,
        profile_level_id: Option<u32>,
    ) -> CodecSpec {
        CodecSpec {
            codec: Codec::H264,
            clock_rate: Frequency::NINETY_KHZ,
            channels: None,
            format: FormatParams {
                level_asymmetry_allowed,
                packetization_mode,
                profile_level_id,
                ..Default::default()
            },
        }
    }

    #[test]
    fn test_h264_profile_matching() {
        struct Case {
            c0: CodecSpec,
            c1: CodecSpec,
            must_match: bool,
            msg: &'static str,
        }

        let cases = [Case {
            c0: h264_codec_spec(None, None, Some(0x42E01F)),
            c1: h264_codec_spec(None, None, Some(0x4DA01F)),
            must_match: true,
            msg:
                "0x42A01F and 0x4DF01F should match, they are both constrained baseline subprofile",
        }, Case {
            c0: h264_codec_spec(None, None, Some(0x42E01F)),
            c1: h264_codec_spec(None, Some(1), Some(0x4DA01F)),
            must_match: false,
            msg:
                "0x42A01F and 0x4DF01F with differing packetization modes should not match",
        },  Case {
            c0: h264_codec_spec(None, Some(0), Some(0x422000)),
            c1: h264_codec_spec(None, None, Some(0x42B00A)),
            must_match: true,
            msg:
                "0x424000 and 0x42B00A should match because they are both the baseline subprofile \
                and the level idc of 0x42F01F will be adjusted to Level1B because the constraint \
                set 3 flag is set"
        }];

        for Case {
            c0,
            c1,
            must_match,
            msg,
        } in cases.into_iter()
        {
            let matched = PayloadParams::match_h264_score(c0, c1).is_some();
            assert_eq!(matched, must_match, "{msg}\nc0: {c0:#?}\nc1: {c1:#?}");
        }
    }
}
