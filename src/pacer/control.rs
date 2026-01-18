use crate::rtp_::Bitrate;

const PACING_FACTOR: f64 = 1.1;

/// Minimum declared bitrate to enable padding.
/// We use 50 kbps as a simple threshold - enough to maintain NAT bindings and RTX state,
/// but not so high as to waste bandwidth on very low bitrate streams (e.g., audio-only).
///
/// libWebRTC's padding is set to the min_bitrate of the lowest simulcast layer (typically 30 kbps)
/// of video. It does not concern audio.
const MIN_PADDING_THRESHOLD: Bitrate = Bitrate::bps(50_000);

/// Target padding rate when above the threshold. This maintains NAT bindings, RTX state,
/// and allows ALR periodic probes to discover higher bandwidth.
const PADDING_TARGET: Bitrate = Bitrate::bps(50_000);

pub(crate) struct PacingResult {
    /// The bitrate at which the pacer may emit padding **when there is no media queued**.
    ///
    /// This value is intentionally an *absolute* target used by the pacer, not a “delta to add
    /// on top of current media”. In practice the **effective padding** over time is the
    /// difference between this target and the media actually sent, because padding is only used
    /// to fill gaps (empty queues), not to continuously top-up while media is flowing.
    pub padding_rate: Bitrate,
    pub pacing_rate: Bitrate,
}

/// Controls the pacing and padding rates.
pub(crate) struct PacerControl {}

impl PacerControl {
    pub fn new() -> Self {
        Self {}
    }

    pub fn calculate(
        &self,
        current_bitrate: Bitrate,
        estimate: Bitrate,
        is_overuse: bool,
    ) -> PacingResult {
        // ALR periodic probes handle bandwidth discovery, not continuous padding.
        let padding_rate = if is_overuse {
            // No padding during overuse
            Bitrate::ZERO
        } else if current_bitrate >= MIN_PADDING_THRESHOLD {
            // Pad to 50 kbps to maintain NAT bindings and RTX state
            PADDING_TARGET
        } else {
            // No padding for very low bitrate scenarios
            Bitrate::ZERO
        };

        // Set pacing rate to smooth out media transmission (burst avoidance).
        // Must be at least the current BWE estimate * factor, but also high enough
        // to allow the padding we want to send.
        let min_pacing_rate = estimate * PACING_FACTOR;
        let pacing_rate = min_pacing_rate.max(padding_rate);

        PacingResult {
            padding_rate,
            pacing_rate,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn padding_enabled_above_threshold() {
        let c = PacerControl::new();
        let current_bitrate = Bitrate::kbps(500);
        let estimate = Bitrate::kbps(1_000);

        let r = c.calculate(current_bitrate, estimate, false);

        // Should pad to 50 kbps when current_bitrate >= 50 kbps
        assert_eq!(r.padding_rate, PADDING_TARGET);
    }

    #[test]
    fn no_padding_below_threshold() {
        let c = PacerControl::new();
        let current_bitrate = Bitrate::kbps(40); // Below 50 kbps threshold
        let estimate = Bitrate::kbps(1_000);

        let r = c.calculate(current_bitrate, estimate, false);

        // No padding for very low bitrate scenarios
        assert_eq!(r.padding_rate, Bitrate::ZERO);
    }

    #[test]
    fn overuse_suppresses_padding() {
        let c = PacerControl::new();
        let current_bitrate = Bitrate::mbps(50);
        let estimate = Bitrate::mbps(40);

        let r = c.calculate(current_bitrate, estimate, true);
        assert_eq!(r.padding_rate, Bitrate::ZERO);
    }
}
