use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::time::Instant;

use super::{BandwithUsage, InterGroupDelayVariation};

const SMOOTHING_COEF: f64 = 0.9;
const OVER_USE_THRESHOLD_DEFAULT_MS: f64 = 12.5;
const OVER_USE_TIME_THRESHOLD_MS: f64 = 10.0;
const MAX_ADOPT_OFFSET_MS: f64 = 15.0;
const THRESHOLD_GAIN: f64 = 4.0;

const K_UP: f64 = 0.0087;
const K_DOWN: f64 = 0.039;

const DELAY_COUNT_RANGE: RangeInclusive<usize> = 60..=1000;

pub(super) struct TrendlineEstimator {
    /// The window size in packets
    window_size: usize,

    /// The first instant we saw, used as zero point.
    zero_time: Option<Instant>,

    /// The history of observed delay variations.
    history: VecDeque<Timing>,

    /// The total number of observed delay variations.
    num_delay_variations: usize,

    /// Accumulated delay.
    accumulated_delay: f64,

    /// Last smoothed delay.
    smoothed_delay: f64,

    /// The adaptive delay threshold.
    delay_threshold: f64,

    /// Previous trend
    previous_trend: f64,

    /// If we are overusing, this contains data about the overuse.
    overuse: Option<Overuse>,

    /// The last time we updated the adaptive threshold.
    last_threshold_update: Option<Instant>,

    /// Our current hypothesis about the bandwidth usage.
    hypothesis: BandwithUsage,
}

impl TrendlineEstimator {
    pub(super) fn new(window_size: usize) -> Self {
        Self {
            window_size,
            zero_time: None,
            history: VecDeque::default(),
            num_delay_variations: 0,
            accumulated_delay: 0.0,
            smoothed_delay: 0.0,
            delay_threshold: OVER_USE_THRESHOLD_DEFAULT_MS,
            previous_trend: 0.0,
            overuse: None,
            last_threshold_update: None,
            hypothesis: BandwithUsage::Normal,
        }
    }

    pub(super) fn add_delay_observation(
        &mut self,
        delay_variation: InterGroupDelayVariation,
        now: Instant,
    ) {
        if self.history.is_empty() {
            self.do_add_to_history(delay_variation, now);
            return;
        }

        self.do_add_to_history(delay_variation, now);
        while self.history.len() > self.window_size {
            let _ = self.history.pop_front();
        }

        if self.history.len() == self.window_size {
            assert!(
                self.history
                    .iter()
                    .zip(self.history.iter().skip(1))
                    .fold(true, |acc, (a, b)| {
                        acc && a.remote_recv_time <= b.remote_recv_time
                    }),
                "Out of order history {:?}",
                self.history
            );
            self.update_trendline(delay_variation, now);
        }
    }

    pub(super) fn hypothesis(&self) -> BandwithUsage {
        self.hypothesis
    }

    fn do_add_to_history(&mut self, variation: InterGroupDelayVariation, now: Instant) {
        if self.zero_time.is_none() {
            self.zero_time = Some(variation.last_remote_recv_time);
        }
        self.num_delay_variations += 1;
        self.num_delay_variations = self.num_delay_variations.min(*DELAY_COUNT_RANGE.end());
        self.accumulated_delay += variation.delay;
        self.smoothed_delay =
            self.smoothed_delay * SMOOTHING_COEF + (1.0 - SMOOTHING_COEF) * self.accumulated_delay;

        // SAFETY: zero_time was set above if it wasn't already Some(_)
        let remote_recv_time = variation
            .last_remote_recv_time
            .saturating_duration_since(self.zero_time.unwrap())
            .as_millis() as f64;
        let timing = Timing {
            at: now,
            remote_recv_time,
            smoothed_delay: self.smoothed_delay,
        };

        self.history.push_back(timing);
    }

    fn update_trendline(
        &mut self,
        variation: InterGroupDelayVariation,
        now: Instant,
    ) -> Option<()> {
        let trend = self.linear_fit().unwrap_or(self.previous_trend);
        trace!("Computed trend {:?}", trend);
        crate::packet::bwe::macros::log_trendline_estimate!(trend);

        self.detect(trend, variation, now);

        Some(())
    }

    fn linear_fit(&self) -> Option<f64> {
        // Simple linear regression to compute slope.
        assert!(self.history.len() > 2);

        let (sum_x, sum_y) = self.history.iter().fold((0.0, 0.0), |acc, t| {
            (acc.0 + t.remote_recv_time, acc.1 + t.smoothed_delay)
        });

        let avg_x = sum_x / self.history.len() as f64;
        let avg_y = sum_y / self.history.len() as f64;

        let (numerator, denomenator) = self.history.iter().fold((0.0, 0.0), |acc, t| {
            let x = t.remote_recv_time;
            let y = t.smoothed_delay;

            let numerator = acc.0 + (x - avg_x) * (y - avg_y);
            let denomenator = acc.1 + (x - avg_x).powi(2);

            (numerator, denomenator)
        });

        if denomenator == 0.0 {
            return None;
        }

        Some(numerator / denomenator)
    }

    fn detect(&mut self, trend: f64, variation: InterGroupDelayVariation, now: Instant) {
        if self.num_delay_variations < 2 {
            self.update_hypothesis(BandwithUsage::Normal);
        }

        let modified_trend = self.num_delay_variations.min(*DELAY_COUNT_RANGE.start()) as f64
            * trend
            * THRESHOLD_GAIN;

        crate::packet::bwe::macros::log_trendline_modified_trend!(
            modified_trend,
            self.delay_threshold
        );
        if modified_trend > self.delay_threshold {
            let overuse = match &mut self.overuse {
                Some(o) => {
                    o.time_overusing += variation.send_delta;
                    o
                }
                None => {
                    let new_overuse = Overuse {
                        count: 0,
                        // Initialize the timer. Assume that we've been
                        // over-using half of the time since the previous
                        // sample.
                        time_overusing: variation.send_delta / 2.0,
                    };
                    self.overuse = Some(new_overuse);

                    self.overuse.as_mut().unwrap()
                }
            };

            overuse.count += 1;
            trace!(
                timeoverusing = overuse.time_overusing,
                trend,
                previous_trend = self.previous_trend,
                "Trendline Estimator: Maybe overusing"
            );

            if overuse.time_overusing > OVER_USE_TIME_THRESHOLD_MS
                && overuse.count > 1
                && trend > self.previous_trend
            {
                self.overuse = None;

                self.update_hypothesis(BandwithUsage::Overuse);
            }
        } else if modified_trend < -self.delay_threshold {
            self.overuse = None;
            self.update_hypothesis(BandwithUsage::Underuse);
        } else {
            self.overuse = None;
            self.update_hypothesis(BandwithUsage::Normal);
        }

        self.previous_trend = trend;
        self.update_threshold(modified_trend, now);
    }

    fn update_threshold(&mut self, modified_trend: f64, now: Instant) {
        if self.last_threshold_update.is_none() {
            self.last_threshold_update = Some(now);
        }

        if modified_trend.abs() > self.delay_threshold + MAX_ADOPT_OFFSET_MS {
            // Avoid adapting the threshold to big latency spikes, caused e.g.,
            // by a sudden capacity drop.
            self.last_threshold_update = Some(now);
            return;
        }

        let k = if modified_trend.abs() < self.delay_threshold {
            K_DOWN
        } else {
            K_UP
        };
        let time_delta_ms = now
            .saturating_duration_since(
                self.last_threshold_update
                    .expect("last_threshold_update must have been set"),
            )
            .as_millis() as f64;
        self.delay_threshold +=
            k * (modified_trend.abs() - self.delay_threshold) * time_delta_ms.min(100.0);
        self.last_threshold_update = Some(now);
        self.delay_threshold = self.delay_threshold.clamp(6.0, 600.0);

        trace!(
            "Adaptive delay variation threshold changed to: {}",
            self.delay_threshold
        );
    }

    fn update_hypothesis(&mut self, new_hypothesis: BandwithUsage) {
        if self.hypothesis == new_hypothesis {
            return;
        }

        debug!("TrendLineEstimator: Setting hypothesis to {new_hypothesis}");
        self.hypothesis = new_hypothesis;
    }
}

#[derive(Debug)]
struct Timing {
    at: Instant,
    remote_recv_time: f64,
    smoothed_delay: f64,
}

struct Overuse {
    count: usize,
    time_overusing: f64,
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use super::{InterGroupDelayVariation, TrendlineEstimator};
    // TODO: Fix tests

    // #[test]
    // fn test_window_size_limit() {
    //     let now = Instant::now();
    //     let remote_recv_time_base = Instant::now();
    //     let mut estimator = TrendlineEstimator::new(Duration::from_secs(1));

    //     estimator.add_delay_observation(delay_variation(0.0, remote_recv_time_base), now);
    //     estimator.add_delay_observation(
    //         delay_variation(10.0, remote_recv_time_base + duration_ms(350)),
    //         now + duration_ms(500),
    //     );

    //     assert_eq!(estimator.history.len(), 2);

    //     estimator.add_delay_observation(100.0, now + duration_ms(1001));

    //     assert_eq!(estimator.history.len(), 2);
    //     assert_eq!(
    //         estimator.history.front().map(|t| t.at),
    //         Some(now + duration_ms(500))
    //     );
    //     assert_eq!(
    //         estimator.history.back().map(|t| t.at),
    //         Some(now + duration_ms(1001))
    //     );
    // }

    // #[test]
    // fn test_window_size_limit_big_jump() {
    //     let now = Instant::now();
    //     let mut estimator = TrendlineEstimator::new(Duration::from_secs(1));

    //     estimator.add_delay_observation(0.0, now);
    //     estimator.add_delay_observation(10.0, now + duration_ms(500));

    //     assert_eq!(estimator.history.len(), 2);

    //     estimator.add_delay_observation(100.0, now + duration_ms(2001));

    //     assert_eq!(estimator.history.len(), 1);
    //     assert_eq!(
    //         estimator.history.front().map(|t| t.at),
    //         Some(now + duration_ms(2001))
    //     );
    // }

    fn duration_ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    fn delay_variation(
        delay: f64,
        send_delta: f64,
        last_remote_recv_time: Instant,
    ) -> InterGroupDelayVariation {
        InterGroupDelayVariation {
            send_delta,
            delay,
            last_remote_recv_time,
        }
    }
}
