use std::time::Instant;

use crate::format::PayloadParams;
use crate::rtp_::VideoOrientation;
use crate::session::Session;
use crate::RtcError;

use super::{ExtensionValues, KeyframeRequestKind, Media, MediaTime, Mid, Pt, Rid, ToPayload};

/// Writer of sample level data.
///
/// Obtained via [`Rtc::writer`][crate::Rtc::writer].
///
/// This is the Sample Level API. For RTP level see
/// [`DirectApi::stream_tx`][crate::change::DirectApi::stream_tx].
pub struct Writer<'a> {
    session: &'a mut Session,
    mid: Mid,
    rid: Option<Rid>,
    ext_vals: ExtensionValues,
}

impl<'a> Writer<'a> {
    /// Create a new writer object.
    ///
    /// The `mid` parameter is required to have a corresponding media in `self.session`.
    pub(crate) fn new(session: &'a mut Session, mid: Mid) -> Self {
        Writer {
            session,
            mid,
            rid: None,
            ext_vals: ExtensionValues::default(),
        }
    }

    /// Get the configured payload parameters for the `mid` this writer is for.
    ///
    /// For the [`Writer::write()`] call, the `pt` must be set correctly.
    pub fn payload_params(&self) -> impl Iterator<Item = &PayloadParams> {
        // This unwrap is OK due to the invariant of self.mid being resolvable
        let media = self.session.media_by_mid(self.mid).unwrap();
        self.session
            .codec_config
            .params()
            .iter()
            .filter(|p| media.remote_pts().contains(&p.pt))
    }

    /// Match the given parameters to the configured parameters for this [`Media`].
    ///
    /// In a server scenario, a certain codec configuration might not have the same
    /// payload type (PT) for two different peers. We will have incoming data with one
    /// PT and need to match that against the PT of the outgoing [`Media`].
    ///
    /// This call performs matching and if a match is found, returns the _local_ PT
    /// that can be used for sending media.
    pub fn match_params(&self, params: PayloadParams) -> Option<Pt> {
        self.session
            .codec_config
            .match_params(params)
            .map(|p| p.pt())
    }

    /// Add on an Rtp Stream Id. This is typically used to separate simulcast layers.
    pub fn rid(mut self, rid: Rid) -> Self {
        self.rid = Some(rid);
        self
    }

    /// Add on audio level and voice activity. These values are communicated in the same
    /// RTP header extension, hence it makes sense setting both at the same time.
    ///
    /// Audio level is measured in negative decibel. 0 is max and a "normal" value might be -30.
    pub fn audio_level(mut self, audio_level: i8, voice_activity: bool) -> Self {
        self.ext_vals.audio_level = Some(audio_level);
        self.ext_vals.voice_activity = Some(voice_activity);
        self
    }

    /// Add video orientation. This can be used by a player on the receiver end to decide
    /// whether the video requires to be rotated to show correctly.
    pub fn video_orientation(mut self, o: VideoOrientation) -> Self {
        self.ext_vals.video_orientation = Some(o);
        self
    }

    /// Set a user extension value.
    pub fn user_extension_value<T: Send + Sync + 'static>(mut self, val: T) -> Self {
        self.ext_vals.user_values.set(val);
        self
    }

    /// Write media.
    ///
    /// This operation fails if the PT doesn't match a negotiated codec, or the RID (`None` or a value)
    /// does not match anything negotiated.
    ///
    /// Regarding `wallclock` and `rtp_time`, the wallclock is the real world time that corresponds to
    /// the `MediaTime`. For an SFU, this can be hard to know, since RTP packets typically only
    /// contain the media time (RTP time). In the simplest SFU setup, the wallclock could simply
    /// be the arrival time of the incoming RTP data (see
    /// [`MediaData::network_time`][crate::media::MediaData]). For better synchronization the SFU
    /// probably needs to weigh in clock drifts and data provided via the statistics.
    ///
    /// If you write media before `IceConnectionState` is `Connected` it will be dropped.
    ///
    /// Panics if [`RtcConfig::set_rtp_mode()`][crate::RtcConfig::set_rtp_mode] is `true`.
    pub fn write(
        self,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: impl Into<Vec<u8>>,
    ) -> Result<(), RtcError> {
        // This (indirect) unwrap is OK due to the invariant of self.mid being resolvable
        let media = media_by_mid_mut(&mut self.session.medias, self.mid);

        if !self.session.codec_config.has_pt(pt) {
            return Err(RtcError::UnknownPt(pt));
        }

        if let Some(rid) = self.rid {
            if !media.rids_rx().expects(rid) && media.rids_rx().is_specific() {
                return Err(RtcError::UnknownRid(rid));
            }
        }

        let data: Vec<u8> = data.into();

        trace!(
            "write {:?} {:?} {:?} time: {:?} len: {}",
            self.mid,
            self.rid,
            pt,
            rtp_time,
            data.len()
        );

        let to_payload = ToPayload {
            pt,
            rid: self.rid,
            wallclock,
            rtp_time,
            data,
            ext_vals: self.ext_vals,
        };

        media.set_to_payload(to_payload)?;

        Ok(())
    }

    /// Test if the kind of keyframe request is possible.
    ///
    /// Sending a keyframe request requires the mechanic to be negotiated as a feedback mechanic
    /// in the SDP offer/answer dance first.
    ///
    /// Specifically these SDP lines would enable FIR and PLI respectively (for payload type 96).
    ///
    /// ```text
    /// a=rtcp-fb:96 ccm fir
    /// a=rtcp-fb:96 nack pli
    /// ```
    pub fn is_request_keyframe_possible(&self, kind: KeyframeRequestKind) -> bool {
        self.session.is_request_keyframe_possible(kind)
    }

    /// Request a keyframe from a remote peer sending media data.
    ///
    /// For SDP: This can fail if the kind of request (PLI or FIR), as specified by the
    /// [`KeyframeRequestKind`], is not negotiated in the SDP answer/offer for this m-line.
    ///
    /// To ensure the call will not fail, use [`Writer::is_request_keyframe_possible()`] to
    /// check whether the feedback mechanism is enabled.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use str0m::Rtc;
    /// # use str0m::media::{Mid, KeyframeRequestKind};
    /// let mut rtc = Rtc::new();
    ///
    /// // add candidates, do SDP negotiation
    /// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
    ///
    /// let writer = rtc.writer(mid).unwrap();
    ///
    /// writer.request_keyframe(None, KeyframeRequestKind::Pli).unwrap();
    /// ```
    pub fn request_keyframe(
        &mut self,
        rid: Option<Rid>,
        kind: KeyframeRequestKind,
    ) -> Result<(), RtcError> {
        if !self.is_request_keyframe_possible(kind) {
            return Err(RtcError::NotReceivingDirection);
        }

        let stream = self
            .session
            .streams
            .rx_by_mid_rid(self.mid, rid)
            .ok_or_else(|| RtcError::NoReceiverSource(rid))?;

        stream.request_keyframe(kind);

        Ok(())
    }
}

/// Get a &mut Media in a slice for a `mid`.
///
/// `mid` must be resolvable or panic will ensue.
fn media_by_mid_mut(medias: &mut [Media], mid: Mid) -> &mut Media {
    medias.iter_mut().find(|m| m.mid() == mid).unwrap()
}
