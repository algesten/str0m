use std::time::Instant;

use crate::format::PayloadParams;
use crate::rtp::VideoOrientation;
use crate::session::Session;
use crate::RtcError;

use super::{ExtensionValues, MediaTime, Mid, Pt, Rid, ToPacketize};

///
pub struct Writer<'a> {
    session: &'a mut Session,
    mid: Mid,
    rid: Option<Rid>,
    ext_vals: ExtensionValues,
}

impl<'a> Writer<'a> {
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
    /// For the [`write()`] call, the `pt` must be set correctly.
    pub fn params(&self) -> &[PayloadParams] {
        let m = self
            .session
            .medias
            .iter()
            .find(|m| m.mid() == self.mid)
            .unwrap();
        m.payload_params()
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

    /// Write media.
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
        if self.session.rtp_mode {
            panic!("Can't use MediaWriter::write when in rtp_mode");
        }

        let media = self
            .session
            .medias
            .iter_mut()
            .find(|m| m.mid() == self.mid)
            .unwrap();

        if !media.has_pt(pt) {
            return Err(RtcError::UnknownPt(pt));
        }

        let max_retain = if media.kind().is_audio() {
            self.session.send_buffer_audio
        } else {
            self.session.send_buffer_video
        };

        let to_packetize = ToPacketize {
            pt,
            rid: self.rid,
            wallclock,
            rtp_time,
            data: data.into(),
            ext_vals: self.ext_vals,
            max_retain,
        };

        media.set_to_packetize(to_packetize)?;

        Ok(())
    }
}
