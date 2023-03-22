use crate::rtp::Direction;
use crate::rtp::Mid;
use crate::Rtc;
use crate::RtcError;

/// Direct change strategy.
///
/// Makes immediate changes to the Rtc session without any Sdp OFFER/ANSWER.
pub struct DirectApi<'a> {
    rtc: &'a mut Rtc,
}

impl<'a> DirectApi<'a> {
    pub(crate) fn new(rtc: &'a mut Rtc) -> Self {
        DirectApi { rtc }
    }

    /// Set direction on some media.
    pub fn set_direction(&mut self, mid: Mid, dir: Direction) -> Result<(), RtcError> {
        let media = self
            .rtc
            .session
            .media_by_mid_mut(mid)
            .ok_or_else(|| RtcError::Other(format!("No media for mid: {}", mid)))?;

        media.set_direction(dir);

        Ok(())
    }

    /// Start the DTLS subsystem.
    pub fn start_dtls(&mut self, active: bool) -> Result<(), RtcError> {
        self.rtc.init_dtls(active)
    }

    /// Start the SCTP over DTLS.
    pub fn start_sctp(&mut self, client: bool) {
        self.rtc.init_sctp(client)
    }
}
