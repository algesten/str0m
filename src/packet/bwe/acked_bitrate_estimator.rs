use std::time::{Duration, Instant};

use crate::rtp::DataSize;
use crate::Bitrate;

pub struct AckedBitrateEstimator {
    /// The initial window to use for the first estimate.
    initial_window: Duration,
    /// The window to use for subsequent estimates after achieving the initial estimate.
    window: Duration,
    /// The estimate of the acked bitrate.
    estimate: Option<Bitrate>,
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
        let Some(update) = self.update_window(receive_time, packet_size, window) else {
            // No update
            return;
        };

        self.estimate = Some(update);
    }

    pub(super) fn current_estimate(&self) -> Option<Bitrate> {
        self.estimate
    }

    fn update_window(
        &mut self,
        receive_time: Instant,
        packet_size: DataSize,
        window: Duration,
    ) -> Option<Bitrate> {
        if self
            .last_update
            .map(|ls| receive_time < ls)
            .unwrap_or(false)
        {
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

        if self.current_window >= window {
            estimate = Some(self.sum / window);
            self.sum = DataSize::ZERO;
            self.current_window -= window;
        }

        self.sum += packet_size;

        estimate
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

        estimator.update(now, DataSize::bytes(0));
        estimator.update(now + Duration::from_millis(250), DataSize::bytes(0));
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
            96800,
            "AckedBitrateEstiamtor should produce the correct bitrate"
        );
    }
}
