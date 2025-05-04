use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp_::Bitrate;

use super::BandwidthUsage;

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
pub(super) struct RateControl {
    state: State,

    estimated_bitrate: Bitrate,
    min_bitrate: Bitrate,
    max_bitrate: Bitrate,

    /// The last observed bitrate calculated based on TWCC data.
    last_observed_bitrate: Option<Bitrate>,
    /// The averaged observed bitrate when we have been in the decrease state.
    averaged_observed_bitrate: MovingAverage,
    /// The last time we updated the estimated bitrate.
    last_estimate_update: Option<Instant>,
    // Last RTT estimate in micro-seconds
    last_rtt: Option<Duration>,
}

impl RateControl {
    pub(super) fn new(start_bitrate: Bitrate, min_bitrate: Bitrate, max_bitrate: Bitrate) -> Self {
        crate::packet::bwe::macros::log_rate_control_state!(State::Increase as i8);

        Self {
            state: State::Increase,

            estimated_bitrate: start_bitrate,
            min_bitrate,
            max_bitrate,

            last_observed_bitrate: None,
            averaged_observed_bitrate: MovingAverage::new(OBSERVED_BIT_RATE_SMOOTHING_FACTOR),
            last_estimate_update: None,
            last_rtt: None,
        }
    }

    /// Update with input from the delay controller.
    pub(super) fn update(
        &mut self,
        signal: Signal,
        observed_bitrate: Bitrate,
        rtt: Option<Duration>,
        now: Instant,
    ) {
        self.last_observed_bitrate = Some(observed_bitrate);
        if let Some(rtt) = rtt {
            self.last_rtt = Some(rtt);
        }

        self.state = self.state.transition(signal);
        crate::packet::bwe::macros::log_rate_control_observed_bitrate!(
            observed_bitrate.as_f64(),
            self.averaged_observed_bitrate
                .average
                .map(|avg| avg.to_string())
                .unwrap_or_default()
        );

        match self.state {
            State::Increase => {
                self.increase(observed_bitrate, now);
            }
            State::Decrease => {
                self.decrease(observed_bitrate, now);
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

    fn increase(&mut self, observed_bitrate: Bitrate, now: Instant) {
        let last_estimate_update = *self.last_estimate_update.get_or_insert(now);

        if self
            .averaged_observed_bitrate
            .upper_range(3.0)
            .map(|upper| observed_bitrate.as_f64() > upper)
            .unwrap_or(false)
        {
            self.averaged_observed_bitrate.reset();
        }

        let since_last_update = now - last_estimate_update;
        assert!(since_last_update >= Duration::ZERO);
        let near_convergence = self.is_near_convergence();

        let mut new_estimate = if near_convergence {
            // Additive increase
            crate::packet::bwe::macros::log_rate_control_applied_change!("increase_additive");
            let response_time =
                self.last_rtt.unwrap_or(Duration::ZERO) + Duration::from_millis(100);

            let alpha =
                0.5 * (since_last_update.as_secs_f64() / response_time.as_secs_f64()).min(1.0);
            let expected_packet_size = self.estimated_packet_size();
            self.estimated_bitrate.as_f64() + (alpha * expected_packet_size).max(1000.0)
        } else {
            // Multiplicative increase
            crate::packet::bwe::macros::log_rate_control_applied_change!("increase_multiplicative");
            let eta = MULTIPLICATIVE_INCREASE_COEF.powf(since_last_update.as_secs_f64().min(1.0));
            let increase = ((eta - 1.0) * self.estimated_bitrate.as_f64()).max(1_000.0);

            self.estimated_bitrate.as_f64() + increase
        };
        let max = observed_bitrate.as_f64() * MAX_ESTIMATE_RATIO;
        new_estimate = max.min(new_estimate);

        self.update_estimate(new_estimate.into(), now);
    }

    fn decrease(&mut self, observed_bitrate: Bitrate, now: Instant) {
        crate::packet::bwe::macros::log_rate_control_applied_change!("decrease");
        if self
            .averaged_observed_bitrate
            .lower_range(3.0)
            .map(|lower| observed_bitrate.as_f64() < lower)
            .unwrap_or(false)
        {
            self.averaged_observed_bitrate.reset();
        }

        let mut new_estimate = observed_bitrate * BETA;

        if self.estimated_bitrate < new_estimate {
            // Avoid increasing the bitrate on overuse
            new_estimate = self.estimated_bitrate;
        }

        self.averaged_observed_bitrate
            .update(observed_bitrate.as_f64());

        #[allow(unused)]
        if let Some(observed_average) = self.averaged_observed_bitrate.average {
            crate::packet::bwe::macros::log_rate_control_observed_bitrate!(
                observed_bitrate.as_u64(),
                observed_average.round() as u64
            );
        }
        // According to https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02#section-6 we
        // should wait until this happens as consequence of the delay control, but libWebRTC does
        // it immediately.
        self.state = State::Hold;
        crate::packet::bwe::macros::log_rate_control_state!(self.state as i8);
        debug!(
            "RateControl: Moving from {} to {} after decreasing estimate",
            State::Decrease,
            State::Hold
        );
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

    fn update_estimate(&mut self, bitrate: Bitrate, now: Instant) {
        self.estimated_bitrate = bitrate.clamp(self.min_bitrate, self.max_bitrate);
        self.last_estimate_update = Some(now);
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
    Increase = 1,
    Hold = 0,
    #[default]
    Decrease = -1,
}

impl State {
    fn transition(&self, signal: Signal) -> Self {
        let new_state = match (self, signal) {
            (_, Signal::Overuse) => Self::Decrease,
            (_, Signal::Underuse) => Self::Hold,
            // https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02#section-6 says to
            // transition to Hold here, but libWebRTC stays in decrease. We will eventually
            // transition to Hold on Underuse.
            (Self::Decrease, Signal::Normal) => Self::Hold,
            (Self::Hold | Self::Increase, Signal::Normal) => Self::Increase,
        };

        if new_state != *self {
            crate::packet::bwe::macros::log_rate_control_state!(new_state as i8);
            debug!("RateControl: Moving from {self} to {new_state} on {signal}");
        }

        new_state
    }
}

impl From<BandwidthUsage> for Signal {
    fn from(value: BandwidthUsage) -> Self {
        match value {
            BandwidthUsage::Overuse => Signal::Overuse,
            BandwidthUsage::Normal => Signal::Normal,
            BandwidthUsage::Underuse => Signal::Underuse,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Hold => write!(f, "hold"),
            State::Increase => write!(f, "increase"),
            State::Decrease => write!(f, "decrease"),
        }
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signal::Overuse => write!(f, "overuse"),
            Signal::Underuse => write!(f, "underuse"),
            Signal::Normal => write!(f, "normal"),
        }
    }
}

/// Exponential moving average
#[derive(Debug)]
pub struct MovingAverage {
    smoothing_factor: f64,
    average: Option<f64>,
    variance: f64,
    std: f64,
}

impl MovingAverage {
    pub fn new(smoothing_factor: f64) -> Self {
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

    fn upper_range(&self, num_std: f64) -> Option<f64> {
        if self.std == 0.0 {
            return None;
        }

        self.average.map(|avg| avg + num_std * self.std)
    }

    fn lower_range(&self, num_std: f64) -> Option<f64> {
        if self.std == 0.0 {
            return None;
        }

        self.average.map(|avg| avg - num_std * self.std)
    }

    pub fn update(&mut self, value: f64) {
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

    fn reset(&mut self) {
        self.average = None;
        self.std = 0.0;
        self.variance = 0.0;
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
            // Tests based on the table in
            // https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02#section-5

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

        fn make_control(estimated_bitrate: u64) -> RateControl {
            RateControl::new(estimated_bitrate.into(), 10_000.into(), 50_000_000.into())
        }

        #[test]
        fn test_initial_estimate() {
            let rate_controller = make_control(100_000);

            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 100_000);
        }

        #[test]
        fn test_normal_yields_multiplicative_increase() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000);
            // Seed last estimate value
            rate_controller.update(Signal::Normal, 85_000.into(), None, now);
            assert_eq!(
                rate_controller.estimated_bitrate().as_u64(),
                101_000,
                "Initial estimate should increase by the minimum(1Kbit/s)"
            );

            rate_controller.update(Signal::Normal, 95_000.into(), None, now + duration_ms(500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 104_963);

            rate_controller.update(Signal::Normal, 97_000.into(), None, now + duration_ms(1000));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 109_081);
        }

        #[test]
        fn test_normal_to_under_use_yields_hold() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000);
            // Seed last estimate value
            rate_controller.update(Signal::Normal, 85_000.into(), None, now);
            assert_eq!(
                rate_controller.estimated_bitrate().as_u64(),
                101_000,
                "Initial estimate should increase by the minimum(1Kbit/s)"
            );

            // Should remain in increase and increase estimate
            rate_controller.update(Signal::Normal, 95_000.into(), None, now + duration_ms(500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 104_963);

            // Should transition to hold
            rate_controller.update(
                Signal::Underuse,
                97_000.into(),
                None,
                now + duration_ms(1000),
            );
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 104_963);

            // Should remain in hold and not modify estimates
            rate_controller.update(
                Signal::Underuse,
                97_000.into(),
                None,
                now + duration_ms(2000),
            );
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 104_963);
        }

        #[test]
        fn test_immediate_overuse() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000);
            // Seed last estimate value
            rate_controller.update(Signal::Normal, 85_000.into(), None, now);

            rate_controller.update(Signal::Overuse, 90_000.into(), None, now + duration_ms(500));
            assert_eq!(
                rate_controller.estimated_bitrate().as_u64(),
                76_500,
                "When overuse is detected we should reduce the estimate to \
                85% of the obeserved rate immediately"
            );
        }

        #[test]
        fn test_immediate_overuse_then_stable() {
            let now = Instant::now();
            let mut rate_controller = make_control(100_000);
            // Seed last estimate value
            rate_controller.update(Signal::Normal, 85_000.into(), Some(duration_ms(80)), now);

            rate_controller.update(Signal::Overuse, 90_000.into(), None, now + duration_ms(500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 76_500);

            rate_controller.update(
                Signal::Overuse,
                75_000.into(),
                None,
                now + duration_ms(1000),
            );
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 63_750);

            rate_controller.update(Signal::Normal, 60_000.into(), None, now + duration_ms(1500));
            // NB: This matches libWebRTC but diverges from the spec
            assert_eq!(
                rate_controller.estimated_bitrate().as_u64(), 66_251,
                "After adjusting on overuse we immediately return to increase on the next normal signal"
            );

            rate_controller.update(Signal::Normal, 60_000.into(), None, now + duration_ms(2500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 71_552,);

            // NB: Additive increase because we are nearing convergence
            rate_controller.update(Signal::Normal, 70_000.into(), None, now + duration_ms(3500));
            assert_eq!(rate_controller.estimated_bitrate().as_u64(), 72552);
        }
    }

    fn duration_ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }
}
