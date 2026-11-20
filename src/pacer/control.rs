use crate::rtp_::Bitrate;

/// Default multiplier on the bandwidth estimate that sets the pacing rate.
pub(crate) const DEFAULT_PACING_FACTOR: f64 = 1.1;

/// Automatic padding target when media is active. This maintains NAT bindings, RTX state,
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
pub(crate) struct PacerControl {
    /// Multiplier on the estimate that sets the pacing rate.
    factor: f64,
}

impl PacerControl {
    pub fn new(factor: f64) -> Self {
        Self { factor }
    }

    pub fn calculate(
        &self,
        has_active_media: bool,
        estimate: Bitrate,
        is_overuse: bool,
        minimum: Bitrate,
    ) -> PacingResult {
        let padding_rate = if is_overuse {
            // No padding during overuse
            Bitrate::ZERO
        } else if has_active_media {
            // Sustain the requested minimum without exceeding estimated capacity.
            // Keep the automatic target for NAT bindings and RTX state.
            PADDING_TARGET.max(minimum).min(estimate)
        } else {
            // No padding when no media is being sent
            Bitrate::ZERO
        };

        // Set pacing rate to smooth out media transmission (burst avoidance).
        // Must be at least the current BWE estimate * factor, but also high enough
        // to allow the padding we want to send.
        let min_pacing_rate = estimate * self.factor;
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
    fn padding_enabled_with_active_media() {
        let c = PacerControl::new(DEFAULT_PACING_FACTOR);
        let estimate = Bitrate::kbps(1_000);

        let r = c.calculate(true, estimate, false, Bitrate::ZERO);

        assert_eq!(r.padding_rate, PADDING_TARGET);
    }

    #[test]
    fn no_padding_without_active_media() {
        let c = PacerControl::new(DEFAULT_PACING_FACTOR);
        let estimate = Bitrate::kbps(1_000);

        let r = c.calculate(false, estimate, false, Bitrate::mbps(2));

        assert_eq!(r.padding_rate, Bitrate::ZERO);
    }

    #[test]
    fn overuse_suppresses_padding() {
        let c = PacerControl::new(DEFAULT_PACING_FACTOR);
        let estimate = Bitrate::mbps(40);

        let r = c.calculate(true, estimate, true, Bitrate::mbps(2));
        assert_eq!(r.padding_rate, Bitrate::ZERO);
    }

    #[test]
    fn minimum_tracks_estimate_without_exceeding_target() {
        let c = PacerControl::new(DEFAULT_PACING_FACTOR);
        let minimum = Bitrate::kbps(800);
        // Both increasing and decreasing estimates must immediately change the cap.
        for (estimate, expected) in [(450, 450), (700, 700), (1000, 800), (300, 300)] {
            let result = c.calculate(true, Bitrate::kbps(estimate), false, minimum);
            assert_eq!(result.padding_rate, Bitrate::kbps(expected));
            assert_eq!(
                result.pacing_rate,
                Bitrate::kbps(estimate) * DEFAULT_PACING_FACTOR
            );
        }
    }

    #[test]
    fn pacing_rate_follows_configured_factor() {
        let c = PacerControl::new(2.5);
        let estimate = Bitrate::mbps(4);

        let r = c.calculate(true, estimate, false, Bitrate::ZERO);

        assert_eq!(r.pacing_rate, estimate * 2.5);
        // The factor must not change the padding rate.
        assert_eq!(r.padding_rate, PADDING_TARGET);
    }

    #[test]
    fn automatic_padding_is_also_capped_by_estimate() {
        let c = PacerControl::new(DEFAULT_PACING_FACTOR);
        for estimate in [Bitrate::ZERO, Bitrate::kbps(20)] {
            let result = c.calculate(true, estimate, false, Bitrate::ZERO);
            assert_eq!(result.padding_rate, estimate);
        }
    }
}
