//! Bandwidth estimation.

use crate::{Rtc, rtp_::Mid};

pub use crate::rtp_::Bitrate;

#[derive(Debug, PartialEq)]
#[non_exhaustive]
/// Bandwidth estimation kind.
pub enum BweKind {
    /// Transport wide congestion control.
    ///
    /// Emits the current estimate with `can_probe: true` when probing becomes
    /// available, initially using the configured starting bitrate. Estimate
    /// updates follow while probing is available. On loss of probing capability,
    /// emits the last reported estimate once with `can_probe: false`, then
    /// suppresses updates until probing becomes available again.
    Twcc {
        /// Estimated available bitrate. Initially this is the configured starting bitrate.
        /// When probing becomes unavailable, this retains the last estimate.
        estimate: Bitrate,
        /// Whether the local BWE can currently probe for capacity.
        ///
        /// Requires BWE to be enabled, SRTP keys, and a sending media section
        /// supporting TWCC feedback and the transport sequence extension.
        /// This does not guarantee that feedback is arriving.
        can_probe: bool,
    },
    /// REMB (Receiver Estimated Maximum Bitrate)
    Remb {
        /// Bitrate reported by the remote receiver.
        estimate: Bitrate,
        /// Media section associated with the report.
        mid: Mid,
    },
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
    /// This discards the current estimator state and starts estimation again
    /// from `init_bitrate`. Normal transitions from audio-only to video sending
    /// do not require a reset: with TWCC negotiated, probing can discover
    /// capacity before video starts. The desired bitrate controls the capacity
    /// the estimator attempts to discover.
    pub fn reset(&mut self, init_bitrate: Bitrate) {
        self.0.session.reset_bwe(init_bitrate);
    }
}
