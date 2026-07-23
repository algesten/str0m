//! Bandwidth estimation.

use crate::poll::RtcMut;
use crate::{Rtc, rtp_::Mid};

pub use crate::rtp_::Bitrate;

#[derive(Debug, PartialEq)]
#[non_exhaustive]
/// Bandwidth estimation kind.
pub enum BweKind {
    /// Transport wide congestion control.
    Twcc(Bitrate),
    /// REMB (Receiver Estimated Maximum Bitrate)
    Remb(Mid, Bitrate),
}

/// Access to the Bandwidth Estimate subsystem.
///
/// The inner `RtcMut` arms the readiness on mutable deref only; see
/// [`crate::poll`].
pub struct Bwe<'a>(pub(crate) RtcMut<'a>);

impl<'a> Bwe<'a> {
    pub(crate) fn new(rtc: &'a mut Rtc) -> Self {
        Bwe(RtcMut::new(rtc))
    }

    /// Configure the desired bitrate.
    ///
    /// Configure the bandwidth estimation system with the desired bitrate.
    /// **Note:** This only has an effect if BWE has been enabled via
    /// [`RtcConfig::enable_bwe`][crate::RtcConfig::enable_bwe].
    ///
    /// * `desired_bitrate` The bitrate you would like to eventually send at. The BWE system will try
    ///   to reach this bitrate by probing with padding packets. You should allocate your media bitrate
    ///   based on the estimated the BWE system produces via
    ///   [`Event::EgressBitrateEstimate`][crate::Event::EgressBitrateEstimate]. This rate might not
    ///   be reached if the network link cannot sustain the desired bitrate.
    ///
    /// ## Example
    ///
    /// Say you have three simulcast video tracks each with a high layer configured at 1.5Mbit/s.
    /// You should then set the desired bitrate to 4.5Mbit/s (or slightly higher). If the network
    /// link can sustain 4.5Mbit/s there will eventually be an
    /// [`Event::EgressBitrateEstimate`][crate::Event::EgressBitrateEstimate] with this estimate.
    pub fn set_desired_bitrate(&mut self, desired_bitrate: Bitrate) {
        let mut m = self.0.mutate();
        m.session.set_bwe_desired_bitrate(desired_bitrate);
        // Reconfiguring BWE only re-arms the estimator/pacer timers; any probing
        // padding is produced later from the timeout path, so no event is queued.
        m.no_events();
    }

    /// Reset the BWE with a new init_bitrate
    ///
    /// # Example
    ///
    /// This method is useful when you initially start with only an audio stream. In this case,
    /// the BWE will report a very low estimated bitrate.
    /// Later, when you start a video stream, the estimated bitrate will be affected by the previous
    /// low bitrate, resulting in a very low estimated bitrate, which can cause poor video quality.
    /// To avoid this, you need to warm up the video stream for a while then calling reset with a
    /// provided init_bitrate.
    ///
    pub fn reset(&mut self, init_bitrate: Bitrate) {
        let mut m = self.0.mutate();
        m.session.reset_bwe(init_bitrate);
        // Resetting the estimator moves no output, only timers.
        m.no_events();
    }
}
