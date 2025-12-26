//! Bandwidth estimation.

use crate::{rtp_::Mid, Rtc};

pub use crate::rtp_::Bitrate;

#[derive(Debug, PartialEq)]
/// Bandwidth estimation kind.
pub enum BweKind {
    /// Transport wide congestion control.
    Twcc(Bitrate),
    /// REMB (Receiver Estimated Maximum Bitrate)
    Remb(Mid, Bitrate),
}

/// Access to the Bandwidth Estimate subsystem.
pub struct Bwe<'a>(pub(crate) &'a mut Rtc);

impl<'a> Bwe<'a> {
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
        self.0.session.set_bwe_desired_bitrate(desired_bitrate);
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
        self.0.session.reset_bwe(init_bitrate);
    }
}
