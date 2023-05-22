use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use super::{BandwithUsage, InterGroupDelayDelta};

const SMOOTHING_COEF: f64 = 0.9;
const OVER_USE_THRESHOLD_DEFAULT_MS: f64 = 12.5;
const OVER_USE_TIME_THRESHOLD: Duration = Duration::from_millis(10);
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
        delay_variation: InterGroupDelayDelta,
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
                        acc && a.remote_recv_time_ms <= b.remote_recv_time_ms
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

    fn do_add_to_history(&mut self, variation: InterGroupDelayDelta, now: Instant) {
        let zero_time = *self
            .zero_time
            .get_or_insert(variation.last_remote_recv_time);

        self.num_delay_variations += 1;
        self.num_delay_variations = self.num_delay_variations.min(*DELAY_COUNT_RANGE.end());
        self.accumulated_delay += variation.delay_delta;
        self.smoothed_delay =
            self.smoothed_delay * SMOOTHING_COEF + (1.0 - SMOOTHING_COEF) * self.accumulated_delay;

        let remote_recv_time = variation.last_remote_recv_time - zero_time;
        let timing = Timing {
            at: now,
            remote_recv_time_ms: remote_recv_time.as_secs_f64() * 1000.0,
            smoothed_delay_ms: self.smoothed_delay,
        };

        self.history.push_back(timing);
    }

    fn update_trendline(&mut self, variation: InterGroupDelayDelta, now: Instant) -> Option<()> {
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
            (acc.0 + t.remote_recv_time_ms, acc.1 + t.smoothed_delay_ms)
        });

        let avg_x = sum_x / self.history.len() as f64;
        let avg_y = sum_y / self.history.len() as f64;

        let (numerator, denomenator) = self.history.iter().fold((0.0, 0.0), |acc, t| {
            let x = t.remote_recv_time_ms;
            let y = t.smoothed_delay_ms;

            let numerator = acc.0 + (x - avg_x) * (y - avg_y);
            let denomenator = acc.1 + (x - avg_x).powi(2);

            (numerator, denomenator)
        });

        if denomenator == 0.0 {
            return None;
        }

        Some(numerator / denomenator)
    }

    fn detect(&mut self, trend: f64, variation: InterGroupDelayDelta, now: Instant) {
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
                        time_overusing: variation.send_delta / 2,
                    };
                    self.overuse = Some(new_overuse);

                    self.overuse.as_mut().unwrap()
                }
            };

            overuse.count += 1;
            trace!(
                timeoverusing = ?overuse.time_overusing,
                trend,
                previous_trend = self.previous_trend,
                "Trendline Estimator: Maybe overusing"
            );

            if overuse.time_overusing > OVER_USE_TIME_THRESHOLD
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
        let abs_modified_trend = modified_trend.abs();

        if abs_modified_trend > self.delay_threshold + MAX_ADOPT_OFFSET_MS {
            // Avoid adapting the threshold to big latency spikes, caused e.g.,
            // by a sudden capacity drop.
            self.last_threshold_update = Some(now);
            return;
        }

        let k = if abs_modified_trend < self.delay_threshold {
            K_DOWN
        } else {
            K_UP
        };
        let time_delta = now
            .saturating_duration_since(
                self.last_threshold_update
                    .expect("last_threshold_update must have been set"),
            )
            .as_millis() as f64;
        self.delay_threshold +=
            k * (abs_modified_trend - self.delay_threshold) * time_delta.min(100.0);
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
    remote_recv_time_ms: f64,
    smoothed_delay_ms: f64,
}

struct Overuse {
    count: usize,
    time_overusing: Duration,
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::packet::bwe::BandwithUsage;

    use super::{InterGroupDelayDelta, TrendlineEstimator};

    #[test]
    fn test_window_size_limit() {
        let now = Instant::now();
        let remote_recv_time_base = Instant::now();
        let mut estimator = TrendlineEstimator::new(20);

        estimator.add_delay_observation(
            delay_variation(0.0, duration_ms(1), remote_recv_time_base),
            now,
        );

        for i in 0..25 {
            estimator.add_delay_observation(
                delay_variation(
                    10.0,
                    duration_ms(1),
                    remote_recv_time_base + duration_ms(350),
                ),
                now + duration_ms(500),
            );
        }

        assert_eq!(estimator.history.len(), 20);
    }

    #[test]
    fn test_overuse() {
        let now = Instant::now();
        let remote_recv_time_base = Instant::now();
        let mut estimator = TrendlineEstimator::new(20);

        for g in 0..5 {
            for i in 0..5 {
                estimator.add_delay_observation(
                    delay_variation(
                        0.0,
                        duration_ms(1),
                        remote_recv_time_base + Duration::from_micros(5_000 * g + i * 40),
                    ),
                    now + duration_ms(g * 100),
                );
            }
        }

        assert_eq!(estimator.hypothesis(), BandwithUsage::Normal);
        assert_eq!(estimator.history.len(), 20);

        estimator.add_delay_observation(
            delay_variation(
                12.0,
                duration_ms(5),
                remote_recv_time_base + Duration::from_micros(25_000),
            ),
            now + duration_ms(600),
        );
        assert_eq!(
            estimator.hypothesis(),
            BandwithUsage::Normal,
            "After getting an initial increasing delay the hypothesis should remain at normal"
        );

        estimator.add_delay_observation(
            delay_variation(
                13.0,
                duration_ms(5),
                remote_recv_time_base + Duration::from_micros(25_140),
            ),
            now + duration_ms(600),
        );
        assert_eq!(
            estimator.hypothesis(),
            BandwithUsage::Normal,
            "After getting an a second increasing delay the hypothesis should remain at normal because we the time overusing threshold hasn't been reached yet"
        );

        estimator.add_delay_observation(
            delay_variation(
                14.0,
                duration_ms(8),
                remote_recv_time_base + Duration::from_micros(25_250),
            ),
            now + duration_ms(600),
        );
        assert_eq!(
            estimator.hypothesis(),
            BandwithUsage::Overuse,
            "After getting a third increasing delay the hypothesis should move to over because we have been overusing for more than 10ms"
        );
    }

    fn duration_ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    fn delay_variation(
        delay: f64,
        send_delta: Duration,
        last_remote_recv_time: Instant,
    ) -> InterGroupDelayDelta {
        InterGroupDelayDelta {
            send_delta,
            delay_delta: delay,
            last_remote_recv_time,
        }
    }
}
