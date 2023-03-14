//! Media (audio/video) related content.

use std::time::Instant;

pub use rtp_::VideoOrientation;

pub use rtp_::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid};
pub use sdp::{Codec, FormatParams};

use crate::{Input, Rtc, RtcError};

mod event;
pub use event::*;

mod codec;
pub use codec::{CodecConfig, PayloadParams};

mod app;
pub(crate) use app::App;

mod receiver;

mod sender;

mod register;

mod mline;
pub(crate) use mline::{MLine, Source};

/// Half internal structures regarding RTP level.
pub mod rtp {
    pub use packet::RtpMeta;
    pub use packet::{CodecExtra, Vp8CodecExtra};
    pub use rtp_::{ExtensionValues, RtpHeader, SeqNo, Ssrc};
}

/// Audio or video media. An m-line in the SDP.
///
/// Instances of [`Media`] are obtained via [`Rtc::media()`][crate::Rtc::media()]. The instance
/// only exists for m-lines that have passed the offer/answer SDP negotiation.
///
/// This is mainly a handle to send outgoing media, but also contains information about the media.
///
/// ```no_run
/// # use str0m::{Rtc, media::Mid};
///
/// let mut rtc = Rtc::new();
///
/// // add candidates, do SDP negotation
/// let mid: Mid = todo!(); // obtain mid from Event::MediaAdded.
///
/// let media = rtc.media(mid).unwrap();
/// ```
pub struct Media<'a> {
    rtc: &'a mut Rtc,
    index: usize,
}

impl Media<'_> {
    fn m_line(&self) -> &MLine {
        self.rtc.m_line(self.index)
    }

    fn m_line_mut(&mut self) -> &mut MLine {
        self.rtc.m_line_mut(self.index)
    }

    /// Identifier of the m-line.
    pub fn mid(&self) -> Mid {
        self.m_line().mid()
    }

    /// The index of the line in the SDP. Once negotiated this cannot change.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Current direction. This can be changed using
    /// [`ChangeSet::set_direction()`][crate::ChangeSet::set_direction()] followed by an SDP negotiation.
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
        self.m_line().direction()
    }

    /// The negotiated payload parameters for this m-line.
    pub fn payload_params(&self) -> &[PayloadParams] {
        self.m_line().payload_params()
    }

    /// Match the given parameters to the configured parameters for this [`Media`].
    ///
    /// In a server scenario, a certain codec configuration might not have the same
    /// payload type (PT) for two different peers. We will have incoming data with one
    /// PT and need to match that against the PT of the outgoing `Media`/m-line.
    ///
    /// This call performs matching and if a match is found, returns the _local_ PT
    /// that can be used for sending media.
    pub fn match_params(&self, params: PayloadParams) -> Option<Pt> {
        self.m_line().match_params(params)
    }

    /// Send outgoing media data via this m-line.
    ///
    /// The `pt` is the payload type for sending and must match the codec of the media data.
    /// This is typically done using [`Media::match_params()`] to compare an incoming set of
    /// parameters with the configured ones in this `Media` instance. It's also possible to
    /// manually match the codec using [`Media::payload_params()`].
    ///
    /// The `now` parameter is required to know the exact time the data is enqueued. This has a
    /// side effect of driving the time of the `Rtc` instance forward. I.e. passing the `now` here
    /// is the same driving time forward with `handle_input()`.
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
    /// # use str0m::{Rtc};
    /// # use str0m::media::{PayloadParams, MediaData, Mid};
    /// # use std::time::Instant;
    /// let mut rtc = Rtc::new();
    ///
    /// // add candidates, do SDP negotation
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
    /// media.writer(pt, Instant::now()).write(data.network_time, data.time, &data.data).unwrap();
    /// ```
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc8852
    pub fn writer(&mut self, pt: Pt, now: Instant) -> Writer<'_> {
        let media = Media {
            rtc: self.rtc,
            index: self.index,
        };

        Writer {
            media,
            now,
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
        self.m_line().is_request_keyframe_possible(kind)
    }

    /// Request a keyframe from a remote peer sending media data.
    ///
    /// This can fail if the kind of request (PLI or FIR), as specified by the
    /// [`KeyframeRequestKind`], is not negotiated in the SDP answer/offer for
    /// this m-line.
    ///
    /// To ensure the call will not fail, use [`Media::is_request_keyframe_possible()`] to
    /// check whether the feedback mechanism is enabled.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use str0m::{Rtc};
    /// # use str0m::media::{Mid, KeyframeRequestKind};
    /// let mut rtc = Rtc::new();
    ///
    /// // add candidates, do SDP negotation
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
        self.m_line_mut().request_keyframe(rid, kind)
    }

    pub(crate) fn new(rtc: &mut Rtc, index: usize) -> Media {
        Media { rtc, index }
    }
}

/// Helper obtained by [`Media::writer()`] to send media.
///
/// This type follows a builder pattern to allow for additional data to be sent as
/// RTP extension headers.
///
/// ```no_run
/// # use str0m::{Rtc};
/// # use str0m::media::{PayloadParams, MediaData, Mid};
/// # use std::time::Instant;
/// let mut rtc = Rtc::new();
///
/// // add candidates, do SDP negotation
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
/// media.writer(pt, Instant::now())
///     .video_orientation(video_orientation)
///     .write(data.network_time, data.time, &data.data).unwrap();
/// ```
pub struct Writer<'a> {
    media: Media<'a>,
    now: Instant,
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

    /// Do the actual write of media. This consumed the builder.
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
    pub fn write(
        mut self,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: &[u8],
    ) -> Result<usize, RtcError> {
        let m_line = self.media.m_line_mut();

        let n = m_line.write(
            self.now,
            self.pt,
            wallclock,
            rtp_time,
            data,
            self.rid,
            self.ext_vals,
        )?;

        // Handle_input with a Input::Timeout can't fail, hence the expect.
        self.media
            .rtc
            .handle_input(Input::Timeout(self.now))
            .expect("handle_input with Timeout to not panic");

        Ok(n)
    }
}
