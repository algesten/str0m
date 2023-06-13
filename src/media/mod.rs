//! Media (audio/video) related content.

use std::time::Instant;

use crate::format::PayloadParams;
pub use crate::rtp::VideoOrientation;
pub use crate::rtp::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid};

use crate::{Rtc, RtcError};

mod event;
pub use event::*;

mod receiver;

mod sender;

mod register;

mod inner;
pub(crate) use inner::{MediaInner, PolledPacket, Source};

/// Half internal structures regarding RTP level.
pub mod rtp {
    pub use crate::rtp::{Extension, ExtensionMap, ExtensionValues};

    // Exposed for integration tests, not for general usage.
    pub use crate::rtp::RtpHeader;
}

/// Audio or video media.
///
/// For SDP: Instances of [`Media`] are obtained via [`Rtc::media()`][crate::Rtc::media()].
/// The instance only exists for lines passed the offer/answer SDP negotiation.
///
/// This is mainly a handle to send outgoing media, but also contains information about the media.
///
/// ```no_run
/// # use str0m::{Rtc, media::Mid};
///
/// let mut rtc = Rtc::new();
///
/// // add candidates, do SDP negotiation
/// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
///
/// let media = rtc.media(mid).unwrap();
/// ```
pub struct Media<'a> {
    rtc: &'a mut Rtc,
    mid: Mid,
}

impl Media<'_> {
    fn inner(&self) -> &MediaInner {
        self.rtc.media_inner(self.mid)
    }

    fn inner_mut(&mut self) -> &mut MediaInner {
        self.rtc.media_inner_mut(self.mid)
    }

    /// Identifier of the media.
    pub fn mid(&self) -> Mid {
        self.inner().mid()
    }

    /// The index of the line in the SDP. Once negotiated this cannot change.
    pub fn index(&self) -> usize {
        self.inner().index()
    }

    /// Current direction. This can be changed using
    /// [`SdpApi::set_direction()`][crate::SdpApi::set_direction()] followed by an SDP negotiation.
    ///
    /// To test whether it's possible to send media with the current direction, use
    ///
    /// ```no_run
    /// # use str0m::media::Media;
    /// let media: Media = todo!(); // Get hold of media row.
    /// if media.direction().is_sending() {
    ///     // media.write(...);
    /// }
    /// ```
    pub fn direction(&self) -> Direction {
        self.inner().direction()
    }

    /// The negotiated payload parameters for this media.
    pub fn payload_params(&self) -> &[PayloadParams] {
        self.inner().payload_params()
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
        self.inner().match_params(params)
    }

    /// Send outgoing media data.
    ///
    /// The `pt` is the payload type for sending and must match the codec of the media data.
    /// This is typically done using [`Media::match_params()`] to compare an incoming set of
    /// parameters with the configured ones in this `Media` instance. It's also possible to
    /// manually match the codec using [`Media::payload_params()`].
    ///
    /// `rid` is [Rtp Stream Identifier][1]. In classic RTP, individual RTP packets are identified
    /// via an RTP header value `SSRC` (Synchronization Source). However it's been proposed to send
    /// the RID in a header extension as an alternative way, making SSRC less important. Currently
    /// this is only used in Chrome when doing Simulcast.
    ///
    /// This operation fails if the current [`Media::direction()`] does not allow sending, the
    /// PT doesn't match a negotiated codec, or the RID (`None` or a value) does not match
    /// anything negotiated.
    ///
    /// ```no_run
    /// # use str0m::Rtc;
    /// # use str0m::media::{MediaData, Mid};
    /// # use str0m::format::PayloadParams;
    /// let mut rtc = Rtc::new();
    ///
    /// // add candidates, do SDP negotiation
    /// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
    ///
    /// let media = rtc.media(mid).unwrap();
    ///
    /// // Get incoming media data from another peer
    /// let data: MediaData = todo!();
    ///
    /// // Match incoming PT to an outgoing PT.
    /// let pt = media.match_params(data.params).unwrap();
    ///
    /// media.writer(pt).write(data.network_time, data.time, &data.data).unwrap();
    /// ```
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc8852
    pub fn writer(&mut self, pt: Pt) -> Writer<'_> {
        let media = Media {
            rtc: self.rtc,
            mid: self.mid,
        };

        Writer {
            media,
            pt,
            rid: None,
            ext_vals: ExtensionValues::default(),
        }
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
        self.inner().is_request_keyframe_possible(kind)
    }

    /// Request a keyframe from a remote peer sending media data.
    ///
    /// For SDP: This can fail if the kind of request (PLI or FIR), as specified by the
    /// [`KeyframeRequestKind`], is not negotiated in the SDP answer/offer for this m-line.
    ///
    /// To ensure the call will not fail, use [`Media::is_request_keyframe_possible()`] to
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
    /// let media = rtc.media(mid).unwrap();
    ///
    /// media.request_keyframe(None, KeyframeRequestKind::Pli).unwrap();
    /// ```
    pub fn request_keyframe(
        &mut self,
        rid: Option<Rid>,
        kind: KeyframeRequestKind,
    ) -> Result<(), RtcError> {
        self.inner_mut().request_keyframe(rid, kind)
    }

    pub(crate) fn new(rtc: &mut Rtc, mid: Mid) -> Media {
        Media { rtc, mid }
    }
}

/// Helper obtained by [`Media::writer()`] to send media.
///
/// This type follows a builder pattern to allow for additional data to be sent as
/// RTP extension headers.
///
/// ```no_run
/// # use str0m::Rtc;
/// # use str0m::media::{MediaData, Mid};
/// # use str0m::format::PayloadParams;
/// let mut rtc = Rtc::new();
///
/// // add candidates, do SDP negotiation
/// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
///
/// let media = rtc.media(mid).unwrap();
///
/// // Get incoming media data from another peer
/// let data: MediaData = todo!();
/// let video_orientation = data.ext_vals.video_orientation.unwrap();
///
/// // Match incoming PT to an outgoing PT.
/// let pt = media.match_params(data.params).unwrap();
///
/// // Send data with video orientation added.
/// media.writer(pt)
///     .video_orientation(video_orientation)
///     .write(data.network_time, data.time, &data.data).unwrap();
/// ```
pub struct Writer<'a> {
    media: Media<'a>,
    pt: Pt,
    rid: Option<Rid>,
    ext_vals: ExtensionValues,
}

impl<'a> Writer<'a> {
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

    /// Do the actual write of media.
    ///
    /// Regarding `wallclock` and `rtp_time`, the wallclock is the real world time that corresponds to
    /// the `MediaTime`. For an SFU, this can be hard to know, since RTP packets typically only
    /// contain the media time (RTP time). In the simplest SFU setup, the wallclock could simply
    /// be the arrival time of the incoming RTP data (see
    /// [`MediaData::network_time`][crate::media::MediaData]). For better synchronization the SFU
    /// probably needs to weigh in clock drifts and data provided via the statistics.
    ///
    /// Notice that incorrect [`Pt`] values would surface as an error here, not when
    /// doing [`Media::writer()`].
    ///
    /// If you write media before `IceConnectionState` is `Connected` it will be dropped.
    ///
    /// Panics if [`RtcConfig::set_rtp_mode()`][crate::RtcConfig::set_rtp_mode] is `true`.
    pub fn write(
        mut self,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: &[u8],
    ) -> Result<(), RtcError> {
        if self.media.inner().rtp_mode {
            panic!("Can't use MediaWriter::write when in rtp_mode");
        }

        let send_buffer_audio = self.media.rtc.session.send_buffer_audio;
        let send_buffer_video = self.media.rtc.session.send_buffer_video;

        let media = self.media.inner_mut();

        media.write(
            self.pt,
            wallclock,
            rtp_time,
            data,
            self.rid,
            self.ext_vals,
            None,
            send_buffer_audio,
            send_buffer_video,
        )?;

        Ok(())
    }

    /// Writes a "raw" RTP packet.
    ///
    /// For info on `wallclock` see [`Writer::write()`].
    ///
    /// The `exts` must contain the mappings for the RTP packet that is written.
    ///
    /// Panics if [`RtcConfig::set_rtp_mode()`][crate::RtcConfig::set_rtp_mode] is `false`.
    ///
    /// WARNING: This is a low level API and is not str0m's primary use case.
    pub fn write_rtp(
        mut self,
        wallclock: Instant,
        packet: &[u8],
        exts: &rtp::ExtensionMap,
    ) -> Result<(), RtcError> {
        if !self.media.inner().rtp_mode {
            panic!("Can't use MediaWriter::write_rtp when not in rtp_mode");
        }

        let send_buffer_audio = self.media.rtc.session.send_buffer_audio;
        let send_buffer_video = self.media.rtc.session.send_buffer_video;

        let media = self.media.inner_mut();

        media.write_rtp(
            self.pt,
            wallclock,
            packet,
            exts,
            send_buffer_audio,
            send_buffer_video,
        )?;

        Ok(())
    }
}
