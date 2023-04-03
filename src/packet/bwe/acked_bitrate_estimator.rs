use std::time::{Duration, Instant};

use crate::rtp::DataSize;
use crate::Bitrate;

// Ported from libWebRTC's src/modules/congestion_controller/goog_cc/bitrate_estimator.cc at
// `9f3ccf291e`.

const SMALL_SAMPLE_THRESHOLD: DataSize = DataSize::bytes(2000);
const SMALL_SAMPLE_UNCERTAINTY: f64 = 25.0;
const UNCERTAINTY: f64 = 10.0;
const ESTIMATE_FLOOR: Bitrate = Bitrate::kbps(40);

pub struct AckedBitrateEstimator {
    /// The initial window to use for the first estimate.
    initial_window: Duration,
    /// The window to use for subsequent estimates after achieving the initial estimate.
    window: Duration,
    /// The estimate of the acked bitrate.
    estimate: Option<Bitrate>,
    /// The estimated variance.
    estimate_var: f64,
    /// The sum in the current window.
    sum: DataSize,
    /// The size of the current window.
    current_window: Duration,
    /// The last time the window was updated.
    last_update: Option<Instant>,
}

impl AckedBitrateEstimator {
    pub(super) fn new(initial_window: Duration, window: Duration) -> Self {
        Self {
            initial_window,
            window,
            estimate: None,
            estimate_var: 50.0,
            sum: DataSize::ZERO,
            current_window: Duration::ZERO,
            last_update: None,
        }
    }

    pub(super) fn update(&mut self, receive_time: Instant, packet_size: DataSize) {
        let window = if self.estimate.is_none() {
            // Use the initial, larger, window at first
            self.initial_window
        } else {
            self.window
        };
        let Some((sample_estimate, is_small_sample)) = self.update_window(receive_time, packet_size, window) else {
            // No update
            return;
        };

        let Some(estimate) = self.estimate else {
            // This is the initial estimate, use it to initialize the estimate.
            self.estimate = Some(sample_estimate);
            return;
        };

        let scale = if is_small_sample && sample_estimate < estimate {
            SMALL_SAMPLE_UNCERTAINTY
        } else {
            UNCERTAINTY
        };

        let sample_estimate_bps = sample_estimate.as_f64();
        let estimate_bps = estimate.as_f64();
        // Define the sample uncertainty as a function of how far away it is from the
        // current estimate. With low values of uncertainty_symmetry_cap_ we add more
        // uncertainty to increases than to decreases. For higher values we approach
        // symmetry.
        let sample_uncertainty =
            scale * (estimate_bps - sample_estimate_bps).abs() / (estimate_bps.max(25_000.0));
        let sample_var = sample_uncertainty.powf(2.0);

        // Update a bayesian estimate of the rate, weighting it lower if the sample
        // uncertainty is large.
        // The bitrate estimate uncertainty is increased with each update to model
        // that the bitrate changes over time.
        let pred_bitrate_estimate_var = self.estimate_var + 5.0;
        let mut new_estimate = (sample_var * estimate_bps
            + pred_bitrate_estimate_var * sample_estimate_bps)
            / (sample_var + pred_bitrate_estimate_var);
        new_estimate = new_estimate.max(ESTIMATE_FLOOR.as_f64());
        self.estimate = Some(Bitrate::bps(new_estimate.ceil() as u64));
        self.estimate_var =
            (sample_var * pred_bitrate_estimate_var) / (sample_var + pred_bitrate_estimate_var);
    }

    pub(super) fn current_estimate(&self) -> Option<Bitrate> {
        self.estimate
    }

    fn update_window(
        &mut self,
        receive_time: Instant,
        packet_size: DataSize,
        window: Duration,
    ) -> Option<(Bitrate, bool)> {
        let time_moved_back = Some(receive_time) < self.last_update;
        if time_moved_back {
            // Time moved backwards, reset state
            self.sum = DataSize::ZERO;
            self.current_window = Duration::ZERO;
            self.last_update = Some(receive_time);

            return None;
        }

        if let Some(last) = self.last_update {
            self.current_window += receive_time - last;
            if receive_time - last >= window {
                // No update for a while, reset estimates.
                self.sum = DataSize::ZERO;
                self.current_window = Duration::from_micros(
                    self.window.as_micros() as u64 % window.as_micros() as u64,
                );
            }
        }

        self.last_update = Some(receive_time);

        let mut estimate = None;

        let mut is_small = false;
        if self.current_window >= window {
            is_small = self.sum < SMALL_SAMPLE_THRESHOLD;
            estimate = Some(self.sum / window);
            self.sum = DataSize::ZERO;
            self.current_window -= window;
        }

        self.sum += packet_size;

        estimate.map(|e| (e, false))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_no_estimate_before_initial_window_has_passed() {
        let now = Instant::now();
        let mut estimator =
            AckedBitrateEstimator::new(Duration::from_millis(500), Duration::from_millis(150));

        estimator.update(now, DataSize::bytes(950));
        estimator.update(now + Duration::from_millis(250), DataSize::bytes(381));
        estimator.update(now + Duration::from_millis(499), DataSize::bytes(1110));

        assert!(
            estimator.current_estimate().is_none(),
            "AckedBitrateEstiamtor should produce no estimate before the initial window is reached"
        );

        estimator.update(now + Duration::from_millis(501), DataSize::bytes(1110));

        let estimate = estimator.current_estimate().expect(
            "After the first window of time has passed AckedBitrateEstimator should produce an estimate"
        );

        assert_eq!(
            estimate.as_u64(),
            39056,
            "AckedBitrateEstiamtor should produce the correct bitrate"
        );
    }

    #[test]
    fn test_correct_estimate_after_initial_window() {
        let now = Instant::now();
        let mut estimator =
            AckedBitrateEstimator::new(Duration::from_millis(500), Duration::from_millis(150));

        estimator.update(now, DataSize::bytes(2500));
        estimator.update(now + Duration::from_millis(250), DataSize::bytes(1392));
        estimator.update(now + Duration::from_millis(499), DataSize::bytes(4021));
        estimator.update(now + Duration::from_millis(500), DataSize::bytes(0));

        assert!(
            estimator.current_estimate().is_some(),
            "After the first window of time has passed AckedBitrateEstimator should produce an estimate"
        );

        estimator.update(now + Duration::from_millis(550), DataSize::bytes(271));
        estimator.update(now + Duration::from_millis(558), DataSize::bytes(813));
        estimator.update(now + Duration::from_millis(648), DataSize::bytes(731));
        /// Will not be counted, part of next window
        estimator.update(now + Duration::from_millis(651), DataSize::bytes(900));

        let estimate = estimator.current_estimate().expect(
            "After the first window of time has passed AckedBitrateEstimator should produce an estimate"
        );

        assert_eq!(
            estimate.as_u64(),
            99530,
            "AckedBitrateEstiamtor should produce the correct bitrate"
        );
    }
}
