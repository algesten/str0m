use crate::rtp_::Bitrate;

const PACING_FACTOR: f64 = 1.1;

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
        current: Bitrate,
        desired: Bitrate,
        estimate: Bitrate,
        send_rate: Bitrate,
    ) -> PacingResult {
        // Calculate padding rate:
        // A non-zero value means: "when the pacer has no media queued, emit padding at this rate".
        // Zero means: "don't emit padding".
        let padding_rate = if desired > estimate {
            // Case 1: App wants more than we know network can handle.
            // We set the padding target to the current estimate to "prove" we can sustain it
            // before the BWE allows us to increase further.
            estimate
        } else if send_rate < current {
            // Case 2: App is sending less than declared (ALR - Application Limited Region)
            // We set the padding target to the current bitrate to maintain the pipe.
            current
        } else {
            // Case 3: App is sending at or above declared rate, no padding needed
            Bitrate::ZERO
        };

        // Set pacing rate to smooth out media transmission (burst avoidance).
        // It must be at least the current bitrate * factor, but also high enough to allow
        // the padding we want to send (which is captured by padding_rate).
        //
        // If we are in Case 1 (probing), padding_rate is current_estimate.
        // If we are in Case 2 (ALR), padding_rate is current_bitrate.
        //
        // So taking max(current_bitrate * 1.1, padding_rate) covers both requirements.
        let min_pacing_rate = current * PACING_FACTOR;
        let pacing_rate = min_pacing_rate.max(padding_rate);

        PacingResult {
            padding_rate,
            pacing_rate,
        }
    }
}
