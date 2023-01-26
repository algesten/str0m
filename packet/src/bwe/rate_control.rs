// TODO: Remove this when we integrated RateControl
#![allow(unused)]

use std::time::{Duration, Instant};

use rtp::Bitrate;

// Recommended values from https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02#section-5
/// Smoothing factor applied to moving stats for observed bitrates when we are in the decreasing
/// state.
const OBSERVED_BIT_RATE_SMOOTHING_FACTOR: f64 = 0.95;
/// The ratio of current estimated bandwidth to use when decreasing the rate.
const BETA: f64 = 0.85;
/// The coefficient used for multiplicative rate increase.
const MULTIPLICATIVE_INCREASE_COEF: f64 = 1.08;
/// The maximal ratio of the observed bitrate that we allow estimating in a single increase.
const MAX_ESTIMATE_RATIO: f64 = 1.5;

/// A type used to estimates a suitable send bitrate.
///
/// Inputs to the rate controller are:
/// * The observed received bitrate(via TWCC feddback).
/// * RTT.
/// * Congestion estimates from the delay controller.
struct RateControl {
    state: State,

    estimated_bitrate: Bitrate,
    min_bitrate: Bitrate,
    max_bitrate: Bitrate,

    /// The last observed bitrate calculated based on TWCC data.
    last_observed_bitrate: Option<Bitrate>,
    /// The averaged observed bitrate when we have been in the decrease state.
    averaged_observed_bitrate: MovingAverage,
    /// The last time we updated the estimated bitrate.
    last_estimate_update: Instant,
    // Last RTT estimate in micro-seconds
    last_rtt_us: Option<f64>,
}

impl RateControl {
    pub(super) fn new(
        start_bitrate: Bitrate,
        min_bitrate: Bitrate,
        max_bitrate: Bitrate,
        now: Instant,
    ) -> Self {
        Self {
            state: State::Increase,

            estimated_bitrate: start_bitrate,
            min_bitrate,
            max_bitrate,

            last_observed_bitrate: None,
            averaged_observed_bitrate: MovingAverage::new(OBSERVED_BIT_RATE_SMOOTHING_FACTOR),
            last_estimate_update: now,
            last_rtt_us: None,
        }
    }

    /// Update the observed bitrate received by the receiver.
    ///
    /// This is typically based on summarising TWCC feedback and correlating with known send sizes
    /// over a window.
    pub(super) fn update_observed_bitrate(&mut self, observed_bitrate: Bitrate) {
        self.last_observed_bitrate = Some(observed_bitrate);
    }

    /// Update the estimated round trip time(from TWCC or RR).
    pub(super) fn update_rtt(&mut self, rtt_us: f64) {
        self.last_rtt_us = Some(rtt_us);
    }

    /// Update with input from the delay controller.
    pub(super) fn update_delay(&mut self, signal: Signal, now: Instant) {
        self.state = self.state.transition(signal);

        match self.state {
            State::Increase => {
                self.increase(now);
            }
            State::Decrease => {
                self.decrease(now);
            }
            State::Hold => {
                // Do nothing
            }
        }
    }

    /// The current estimated bitrate.
    pub(super) fn estimated_bitrate(&self) -> Bitrate {
        self.estimated_bitrate
    }

    fn increase(&mut self, now: Instant) {
        let since_last_update = ((now - self.last_estimate_update).as_millis() as f64) / 1000.0;

        let new_estimate = if self.is_near_convergence() {
            // Additive increase
            let response_time_ms = self.last_rtt_us.map(|rtt| rtt / 1000.0).unwrap_or(0.0) + 100.0;
            let alpha = 0.5 * (since_last_update / response_time_ms).min(1.0);
            let expected_packet_size = self.estimated_packet_size();
            self.estimated_bitrate.as_f64() + (alpha * expected_packet_size).max(1000.0)
        } else {
            // Multiplicative increase
            let eta = MULTIPLICATIVE_INCREASE_COEF.powf(since_last_update.min(1.0));
            eta * self.estimated_bitrate.as_f64()
        };
        let max = self
            .last_observed_bitrate
            .map(|r| r.as_f64() * MAX_ESTIMATE_RATIO);

        let restricted_estimate = max.map(|m| m.min(new_estimate)).unwrap_or(new_estimate);
        self.update_estimate(restricted_estimate, now);
    }

    fn decrease(&mut self, now: Instant) {
        let new_estimate = BETA * self.estimated_bitrate.as_f64();
        if let Some(last_observed_bitrate) = self.last_observed_bitrate {
            self.averaged_observed_bitrate
                .update(last_observed_bitrate.as_f64());
        }
        self.update_estimate(new_estimate, now);
    }

    fn is_near_convergence(&self) -> bool {
        // Not near convergence until we have valid statistics
        if !self.averaged_observed_bitrate.valid() {
            return false;
        }
        let Some(last_observed_bitrate) = self.last_observed_bitrate else {
            return false;
        };

        // Near convergence if the observed bandwidth is within 3 standard deviations of
        // the moving average when we have been in the decrease state.
        self.averaged_observed_bitrate
            .within_std(last_observed_bitrate.as_f64(), 3.0)
    }

    fn update_estimate(&mut self, new_estimate: f64, now: Instant) {
        let bitrate: Bitrate = new_estimate.into();
        self.estimated_bitrate = bitrate.clamp(self.min_bitrate, self.max_bitrate);
        self.last_estimate_update = now;
    }

    fn estimated_packet_size(&self) -> f64 {
        // Assume 30 FPS video dominates the send rate
        let bits_per_frame = self.estimated_bitrate.as_f64() / 30.0;
        let packets_per_frame = (bits_per_frame / (1200.0 / 8.0)).ceil();

        bits_per_frame / packets_per_frame
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Overuse,
    Underuse,
    Normal,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum State {
    Hold,
    #[default]
    Increase,
    Decrease,
}

impl State {
    fn transition(&self, signal: Signal) -> Self {
        match (self, signal) {
            (_, Signal::Overuse) => Self::Decrease,
            (_, Signal::Underuse) => Self::Hold,
            (Self::Decrease, Signal::Normal) => Self::Hold,
            (Self::Hold | Self::Increase, Signal::Normal) => Self::Increase,
        }
    }
}

/// Exponential moving average
#[derive(Debug)]
struct MovingAverage {
    smoothing_factor: f64,
    average: Option<f64>,
    variance: f64,
    std: f64,
}

impl MovingAverage {
    fn new(smoothing_factor: f64) -> Self {
        Self {
            smoothing_factor,
            average: None,
            variance: 0.0,
            std: 0.0,
        }
    }

    fn within_std(&self, value: f64, num_std: f64) -> bool {
        let Some(average) = self.average else {
            return false;
        };

        let floor = average - self.std * num_std;
        let ceil = average + self.std * num_std;

        floor <= value && value <= ceil
    }

    fn update(&mut self, value: f64) {
        let average = match self.average {
            Some(average) => {
                let delta = value - average;
                let new_average = average + self.smoothing_factor * delta;
                let new_variance = (1.0 - self.smoothing_factor)
                    * (self.variance + self.smoothing_factor * delta.powf(2.0));

                self.variance = new_variance;
                self.std = new_variance.sqrt();

                new_average
            }
            None => value,
        };

        self.average = Some(average);
    }

    fn valid(&self) -> bool {
        self.average.is_some()
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::{RateControl, Signal, State};

    mod state {
        use super::{Signal, State};

        #[test]
        fn test_state_transitions() {
            // Tests based on the table in https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02#section-5

            // Hold
            let hold = State::Hold;
            assert_eq!(hold.transition(Signal::Overuse), State::Decrease);
            assert_eq!(hold.transition(Signal::Normal), State::Increase);
            assert_eq!(hold.transition(Signal::Underuse), State::Hold);

            // Increase
            let increase = State::Increase;
            assert_eq!(increase.transition(Signal::Overuse), State::Decrease);
            assert_eq!(increase.transition(Signal::Normal), State::Increase);
            assert_eq!(increase.transition(Signal::Underuse), State::Hold);

            // Decrease
            let decrease = State::Decrease;
            assert_eq!(decrease.transition(Signal::Overuse), State::Decrease);
            assert_eq!(decrease.transition(Signal::Normal), State::Hold);
            assert_eq!(decrease.transition(Signal::Underuse), State::Hold);
        }
    }

    mod rate_controller {
        use std::time::Instant;

        use super::{duration_ms, RateControl, Signal};

        fn make_control(estimated_bitrate: u64, now: Instant) -> RateControl {
            RateControl::new(
                estimated_bitrate.into(),
                10_000.into(),
                50_000_000.into(),
                now,
            )
        }

        #[test]
        fn test_initial_estimate() {
            let now = Instant::now();
            let rate_controller = make_control(100_000, now);

            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 100_000);
        }

        #[test]
        fn test_normal_yields_multiplicative_increase() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000, now);

            rate_controller.update_delay(Signal::Normal, now + duration_ms(500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 103924);

            rate_controller.update_delay(Signal::Normal, now + duration_ms(1000));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 108001);
        }

        #[test]
        fn test_normal_to_under_use_yields_hold() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000, now);

            // Should remain in increase and increase estimate
            rate_controller.update_delay(Signal::Normal, now + duration_ms(500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 103924);

            // Should transition to hold
            rate_controller.update_delay(Signal::Underuse, now + duration_ms(1000));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 103924);

            // Should remain in hold and not modify estimates
            rate_controller.update_delay(Signal::Underuse, now + duration_ms(2000));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 103924);
        }

        #[test]
        fn test_immediate_overuse() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000, now);

            rate_controller.update_delay(Signal::Overuse, now + duration_ms(500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 85_000);

            rate_controller.update_delay(Signal::Overuse, now + duration_ms(100));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 72250);
        }

        #[test]
        fn test_immediate_overuse_then_stable() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000, now);
            rate_controller.update_rtt(80.0 * 1000.0);

            rate_controller.update_delay(Signal::Overuse, now + duration_ms(500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 85_000);

            rate_controller.update_observed_bitrate(75_000.into());
            rate_controller.update_delay(Signal::Overuse, now + duration_ms(1000));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 72250);

            rate_controller.update_observed_bitrate(70_000.into());
            rate_controller.update_delay(Signal::Normal, now + duration_ms(1500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 72250);

            rate_controller.update_delay(Signal::Normal, now + duration_ms(2500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 78030);

            rate_controller.update_observed_bitrate(76_000.into());
            rate_controller.update_delay(Signal::Overuse, now + duration_ms(3000));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 66326);

            rate_controller.update_delay(Signal::Normal, now + duration_ms(3500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 66326);

            // NB: Additive increase because we are nearing convergence
            rate_controller.update_delay(Signal::Normal, now + duration_ms(3550));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 67326);
        }
    }

    fn duration_ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }
}
