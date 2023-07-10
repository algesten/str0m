use std::time::Instant;

use crate::format::PayloadParams;
use crate::session::Session;
use crate::RtcError;

use super::{MediaTime, Mid, Pt, StreamId};

///
pub struct Writer<'a> {
    session: &'a mut Session,
    mid: Mid,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(session: &'a mut Session, mid: Mid) -> Self {
        Writer { session, mid }
    }

    pub fn params(&self) -> &[PayloadParams] {
        let m = self
            .session
            .medias
            .iter()
            .find(|m| m.mid() == self.mid)
            .unwrap();
        m.payload_params()
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
        mut self,
        pt: Pt,
        wallclock: Instant,
        rtp_time: MediaTime,
        data: &[u8],
    ) -> Result<(), RtcError> {
        if self.session.rtp_mode {
            panic!("Can't use MediaWriter::write when in rtp_mode");
        }

        let send_buffer_audio = self.session.send_buffer_audio;
        let send_buffer_video = self.session.send_buffer_video;

        let media = self
            .session
            .medias
            .iter()
            .find(|m| m.mid() == self.mid)
            .unwrap();

        let Some(StreamId { ssrc, ssrc_rtx, .. }) = media.streams_tx().first() else {
            return Err(RtcError::NoSenderSource);
        };

        let stream = self.session.streams.declare_stream_tx(*ssrc, *ssrc_rtx);

        // TODO: continue here.
        // stream.write_rtp(
        //     pt, seq_no, rtp_time, wallclock, marker, ext_vals, nackable, payload,
        // );

        Ok(())
    }
}
