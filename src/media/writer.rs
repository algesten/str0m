use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::RtcError;
use crate::format::PayloadParams;
use crate::rtp_::AbsCaptureTime;
use crate::rtp_::MidRid;
use crate::rtp_::VideoOrientation;
use crate::session::Session;

use super::dtmf_sender::DtmfTone;
use super::{
    Dtmf, ExtensionValues, KeyframeRequestKind, Media, MediaTime, Mid, Pt, Rid, ToPayload,
};

/// Writer of frame level data and DTMF tones.
///
/// Obtained via [`Rtc::writer`][crate::Rtc::writer].
///
/// Frame writing is limited to sample mode; tone sending and feedback also work
/// in RTP mode. For individual RTP packets see
/// [`DirectApi::stream_tx`][crate::change::DirectApi::stream_tx].
pub struct Writer<'a> {
    session: &'a mut Session,
    mid: Mid,
    rid: Option<Rid>,
    start_of_talkspurt: Option<bool>,
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
            start_of_talkspurt: None,
            ext_vals: ExtensionValues::default(),
        }
    }

    /// Get the configured payload parameters for the `mid` this writer is for.
    ///
    /// SDP media use the negotiated payloads; Direct API media use the configured
    /// codecs for their media kind. Use an audio/video PT for [`Self::write`] or
    /// a telephone-event PT for [`Self::write_dtmf`].
    pub fn payload_params(&self) -> impl Iterator<Item = &PayloadParams> {
        // This unwrap is OK due to the invariant of self.mid being resolvable
        let media = self.session.media_by_mid(self.mid).unwrap();
        self.session
            .codec_config
            .all_for_kind(media.kind())
            .filter(move |p| media.is_direct_api() || media.remote_pts().contains(&p.pt))
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

    /// First packet of a talkspurt, that is the first packet after a silence period during
    /// which packets have not been transmitted contiguously.
    ///
    /// For audio only when dtx or silence suppression is enabled.
    /// This will set the marker bit in the RTP header.
    pub fn start_of_talkspurt(mut self, start_of_talkspurt: bool) -> Self {
        self.start_of_talkspurt = Some(start_of_talkspurt);
        self
    }

    /// Add video orientation. This can be used by a player on the receiver end to decide
    /// whether the video requires to be rotated to show correctly.
    pub fn video_orientation(mut self, o: VideoOrientation) -> Self {
        self.ext_vals.video_orientation = Some(o);
        self
    }

    /// Set absolute capture time for this frame.
    pub fn abs_capture_time(mut self, capture_time: AbsCaptureTime) -> Self {
        self.ext_vals.abs_capture_time = Some(capture_time);
        self
    }

    /// Set the minimum and maximum playout delay values. This can be used by a player
    /// on the receiver end to determine the size of the jitter buffer.
    pub fn playout_delay(mut self, min: MediaTime, max: MediaTime) -> Self {
        self.ext_vals.play_delay_min = Some(min);
        self.ext_vals.play_delay_max = Some(max);
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
    /// Raw telephone-event payloads return [`RtcError::UnknownPt`] here.
    /// Use [`Self::write_dtmf`] to send a tone, or the RTP API for individual reports.
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
        data: impl Into<Arc<[u8]>>,
    ) -> Result<(), RtcError> {
        assert!(
            !self.session.rtp_mode,
            "In rtp_mode use direct_api().stream_tx().write_rtp() for media packets"
        );

        // This (indirect) unwrap is OK due to the invariant of self.mid being resolvable
        let media = media_by_mid_mut(&mut self.session.medias, self.mid);

        if !self
            .session
            .codec_config
            .iter()
            .any(|p| p.pt() == pt && !p.spec().codec.is_telephone_event())
        {
            return Err(RtcError::UnknownPt(pt));
        }

        if let Some(rid) = self.rid {
            if !media.rids_tx().contains(rid) {
                return Err(RtcError::UnknownRid(rid));
            }
        }

        let data: Arc<[u8]> = data.into();

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
            start_of_talk_spurt: self.start_of_talkspurt.unwrap_or(false),
            ext_vals: self.ext_vals,
        };

        media.set_to_payload(to_payload)?;

        Ok(())
    }

    /// Send a DTMF telephone-event tone (RFC 4733).
    ///
    /// Available in both RTP and sample modes.
    ///
    /// The reports are sent on the transmit stream that carries the audio, sharing its SSRC
    /// and sequence number series as RFC 4733 Section 2.5.1.2 requires. In RTP mode str0m
    /// allocates those sequence numbers from the same cursor that
    /// [`StreamTx::write_rtp`][crate::rtp::StreamTx::write_rtp] advances, so a stream
    /// that mixes application RTP with tones must take its own sequence numbers from
    /// [`StreamTx::next_seq_no`][crate::rtp::StreamTx::next_seq_no] rather than a
    /// private counter.
    ///
    /// Queues duration updates at 20 ms intervals and sends the three final reports
    /// as one burst, matching MSRTC/libwebrtc sender scheduling rather than RFC 4733's
    /// recommended interval spacing. Only the first packet has the RTP marker bit. Long tones are
    /// split into contiguous segments when the 16-bit duration field is exhausted.
    /// Durations shorter than one tick of the negotiated clock use one tick, since RFC 4733
    /// Section 2.3.5 reserves a zero duration for state events. Durations longer than one
    /// hour are clamped.
    ///
    /// `volume` is the RFC 4733 level in -dBm0, from 0 (loudest) to 63 (quietest).
    /// Values above 63 return [`RtcError::InvalidDtmfVolume`]. The legacy
    /// hook-flash event has no tone level and is always sent with volume zero.
    /// This is separate from the RTP header extension set by [`Self::audio_level`].
    ///
    /// `wallclock` and `rtp_time` mark the start of the tone, as in [`Self::write`].
    /// Tones are sent in call order per transmit stream, with at least 70 ms
    /// between tones. Different RIDs have independent queues. Starts that
    /// are too close are delayed, along with their RTP timestamps; larger
    /// caller-supplied gaps are preserved. No tone gap is inserted between
    /// continuation segments. The selected RID and
    /// header extensions apply to the generated reports.
    ///
    /// Active and queued tones are cancelled when the media stops sending.
    /// Enabling sending again does not resume them. Tones also stop if renegotiation
    /// removes their payload type or event from the peer's supported set.
    /// Removing or resetting a transmit stream, or withdrawing its RID, cancels
    /// its pending tones.
    ///
    /// This API supports RFC 4733 long-event segments. Peers such as MSRTC's native
    /// receiver may treat those segments as separate digits; use single-segment
    /// durations when targeting such peers.
    ///
    /// `pt` must be a negotiated telephone-event payload type. Enable support with
    /// [`RtcConfig::enable_telephone_event`][crate::RtcConfig::enable_telephone_event].
    /// Select the payload whose clock matches the audio codec's
    /// [`CodecSpec::rtp_clock_rate`][crate::format::CodecSpec::rtp_clock_rate].
    /// An unknown or unnegotiated PT returns [`RtcError::UnknownPt`], an unsupported
    /// event returns [`RtcError::UnsupportedDtmfEvent`], and an unknown RID returns
    /// [`RtcError::UnknownRid`]. A non-sending media direction returns
    /// [`RtcError::NotSendingDirection`], and a missing transmit stream returns
    /// [`RtcError::NoSenderSource`].
    ///
    /// ```
    /// use std::time::{Duration, Instant};
    /// use str0m::{Rtc, RtcError};
    /// use str0m::media::{Dtmf, MediaTime, Mid, Pt};
    ///
    /// fn send_digit(rtc: &mut Rtc, mid: Mid, pt: Pt, now: Instant) -> Result<(), RtcError> {
    ///     rtc.writer(mid).unwrap().write_dtmf(
    ///         pt, now, MediaTime::ZERO, Dtmf::D5, Duration::from_millis(100), 10,
    ///     )
    /// }
    /// ```
    pub fn write_dtmf(
        self,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        event: Dtmf,
        duration: Duration,
        volume: u8,
    ) -> Result<(), RtcError> {
        if volume > 63 {
            return Err(RtcError::InvalidDtmfVolume(volume));
        }

        let Some(clock_rate) = self
            .session
            .codec_config
            .iter()
            .find(|p| p.pt() == pt && p.spec().codec.is_telephone_event())
            .map(|p| p.spec().rtp_clock_rate())
        else {
            return Err(RtcError::UnknownPt(pt));
        };

        let media = media_by_mid_mut(&mut self.session.medias, self.mid);
        if !media.direction().is_sending() {
            return Err(RtcError::NotSendingDirection(media.direction()));
        }
        if !media.has_telephone_event(pt) {
            return Err(RtcError::UnknownPt(pt));
        }
        if let Some(rid) = self.rid {
            if !media.rids_tx().contains(rid) {
                return Err(RtcError::UnknownRid(rid));
            }
        }
        let event_code = event.event_code();
        if !media.supports_telephone_event(pt, event_code) {
            return Err(RtcError::UnsupportedDtmfEvent(event_code));
        }
        // A tone is queued against the concrete rid of the stream that carries it, which
        // `stream_tx_by_midrid` resolves deterministically when the caller named no rid.
        let stream = self
            .session
            .streams
            .stream_tx_by_midrid(MidRid(self.mid, self.rid))
            .ok_or(RtcError::NoSenderSource)?;
        let rid = stream.rid();

        media.queue_dtmf(DtmfTone {
            pt,
            rid,
            rtp_time,
            wallclock,
            event: event_code,
            volume: if event == Dtmf::Flash { 0 } else { volume },
            duration,
            clock_rate,
            ext_vals: self.ext_vals,
        });
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
    /// # use std::time::Instant;
    /// # use str0m::Rtc;
    /// # use str0m::media::{Mid, KeyframeRequestKind};
    /// let mut rtc = Rtc::new(Instant::now());
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

        let midrid = MidRid(self.mid, rid);

        let stream = self
            .session
            .streams
            .stream_rx_by_midrid(midrid, false)
            .ok_or(RtcError::NoReceiverSource(rid))?;

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
