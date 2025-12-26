use crate::packet::bwe::NEAR_DESIRED_RATIO;
use crate::rtp_::Bitrate;

const PACING_FACTOR: f64 = 1.1;
/// When padding to close the gap to the current estimate, leave some headroom to avoid
/// persistent queue build-up and overuse oscillations near capacity.
const PADDING_HEADROOM: f64 = 0.90;
/// When we decide we are "near desired", cap how much we may increase the padding target above
/// the current estimate.
///
/// This keeps the behavior a *creep* even if `NEAR_DESIRED_RATIO` is tuned lower.
const NEAR_DESIRED_MAX_CREEP_OVER_ESTIMATE: f64 = 0.05; // +5%

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

/// Calculates pacing and padding rates based on current network conditions and application requirements.
///
/// # Pacing Strategy
///
/// The pacer ensures media is sent smoothly to avoid network congestion bursts.
/// We calculate two key rates:
///
/// 1. **Padding Rate**: A send-rate used for padding **only when there is no media queued**.
/// 2. **Pacing Rate**: The maximum rate at which we drain the packet queue.
///
pub(crate) struct PacerControl {
    // No internal state needed yet, but keeping struct for future extensibility
}

impl PacerControl {
    pub fn new() -> Self {
        Self {}
    }

    pub fn calculate(
        &self,
        desired: Bitrate,
        estimate: Bitrate,
        send_rate: Bitrate,
        app_rate: Bitrate,
        is_overuse: bool,
    ) -> PacingResult {
        // `send_rate` is the TWCC-acked send-rate (receiver-confirmed throughput). We keep this
        // terminology consistent across the codebase, but padding decisions are driven by
        // `app_rate` (what we actually emitted excluding padding/probes).
        let _ = send_rate;

        // Calculate padding rate:
        // A non-zero value means: "when the pacer has no media queued, emit padding at this rate".
        // Zero means: "don't emit padding".
        //
        // We compute an absolute target, then request padding if the application is sending below
        // that target (ALR / app-limited).
        let padding_target = if desired <= Bitrate::ZERO {
            Bitrate::ZERO
        } else if is_overuse {
            // If the delay-based detector signals overuse, don't add padding. This gives queues a
            // chance to drain before the BWE rate controller commits to a multiplicative decrease.
            Bitrate::ZERO
        } else if estimate >= desired * NEAR_DESIRED_RATIO {
            // Near desired: avoid probe bursts and instead allow a small, controlled creep via padding.
            // We cap the creep to a small percentage over the estimate.
            let creep_cap = estimate * (1.0 + NEAR_DESIRED_MAX_CREEP_OVER_ESTIMATE);
            desired.min(creep_cap)
        } else {
            // Far from desired: close the gap to the current estimate (probes handle fast ramp-ups).
            desired.min(estimate * PADDING_HEADROOM)
        };

        let padding_rate = if app_rate < padding_target {
            padding_target
        } else {
            Bitrate::ZERO
        };

        // Set pacing rate to smooth out media transmission (burst avoidance).
        // It must be at least the current BWE estimate * factor, but also high enough to allow
        // the padding we want to send (captured by padding_rate).
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
    fn near_desired_creeps_padding_to_desired() {
        let c = PacerControl::new();
        let desired = Bitrate::kbps(1_000);
        let estimate = desired * NEAR_DESIRED_RATIO;
        let send_rate = Bitrate::kbps(1_000);
        // Simulate ALR (app is sending below target); padding should fill the gap.
        let app_rate = Bitrate::kbps(250);

        let r = c.calculate(desired, estimate, send_rate, app_rate, false);
        let expected = desired.min(estimate * (1.0 + NEAR_DESIRED_MAX_CREEP_OVER_ESTIMATE));
        // Bitrate is float-backed; allow a 1 bps epsilon.
        assert!(r.padding_rate <= expected + Bitrate::bps(1));
        assert!(r.padding_rate + Bitrate::bps(1) >= expected);
    }

    #[test]
    fn far_from_desired_sticks_to_estimate_for_padding() {
        let c = PacerControl::new();
        let desired = Bitrate::kbps(2_000);
        let estimate = Bitrate::kbps(800); // well below desired*0.95
        let send_rate = Bitrate::kbps(1_000);
        // App is sending below estimate, so we should pad up to estimate.
        let app_rate = Bitrate::kbps(250);

        let r = c.calculate(desired, estimate, send_rate, app_rate, false);
        assert_eq!(r.padding_rate, estimate * PADDING_HEADROOM);
    }

    #[test]
    fn overuse_suppresses_padding() {
        let c = PacerControl::new();
        let desired = Bitrate::mbps(50);
        let estimate = Bitrate::mbps(40);
        let send_rate = Bitrate::mbps(40);
        let app_rate = Bitrate::mbps(3);

        let r = c.calculate(desired, estimate, send_rate, app_rate, true);
        assert_eq!(r.padding_rate, Bitrate::ZERO);
    }
}
