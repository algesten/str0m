#![allow(dead_code)]
// ^- TODO: remove

// ref: https://webrtc.googlesource.com/src/+/14e2779a6ccdc67038ed2069a5732dd41617c6f0/modules/congestion_controller/goog_cc/loss_based_bwe_v2.cc

use std::cmp::max;
use std::cmp::min;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::rtp::Bitrate;
use crate::rtp::DataSize;

use super::super_instant::SuperInstant;

// WIP: temporary definitions to be removed when integrating with the rest of the bwe system
pub struct PacketResult {
    pub receive_time: Option<Instant>,
    pub first_send_time: Instant,
    pub size: DataSize,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DelayDetectorBandwidthUsage {
    Normal,
    Underusing,
    Overusing,
}

/// Loss Controller
///
/// Usage:
///
/// let lbc = LossController::new();
///
/// lcb.set_min_bitrate(min_bitrate);
/// lbc.set_max_bitrate(max_bitrate);
/// lbc.set_acknowledged_bitrate(acknowledged_bitrate);
/// lbc.set_delay_based_estimated_bitrate(delay_based_estimated_bitrate);
/// lbc.set_bandwidth_estimate(bandwidth_estimate); // sideband bandwidth estimate
///
/// // when receiving twcc reports
/// lbc.update_bandwidth_estimate(
///     packet_results,
///     delay_based_estimate,
///     acknowledged_bitrate,
///     delay_detector_state,
///     probe_bitrate,
///     upper_link_capacity,
///     in_alr,
/// );
///
/// let LossBasedBweResult { bandwidth_estimate, state } = lbc.get_loss_based_result();
///
///

// Internal loss controller configuration
// TODO: having this as a struct would be better, especially for the unit tests

const CONF_OBSERVATION_WINDOW_SIZE: usize = 20; // minimum is 2
const CONF_OBSERVATION_DURATION_LOWER_BOUND: Duration = Duration::from_millis(0);
const CONF_TRENDLINE_INTEGRATION_ENABLED: bool = false;
const CONF_TRENDLINE_OBSERVATIONS_WINDOW_SIZE: usize = 40;
const CONF_TEMPORAL_WEIGHT_FACTOR: f64 = 0.9;
const CONF_INSTANT_UPPER_BOUND_TEMPORAL_WEIGHT_FACTOR: f64 = 0.9;
const CONF_INSTANT_UPPER_BOUND_LOSS_OFFSET: f64 = 0.05;
const CONF_INSTANT_UPPER_BOUND_BANDWIDTH_BALANCE: f64 = 75_000.0; // 75 kbps
const CONF_HIGH_LOSS_RATE_THRESHOLD: f64 = 1.0;
const CONF_SLOPE_OF_BWE_HIGH_LOSS_FUNCTION: f64 = 1000.0;
const CONF_BANDTIDTH_CAP_AT_HIGH_LOSS_RATE: f64 = 50_000.0; // 500 kbps
const CONF_INITIAL_INHERENT_LOSS_ESTIMATE: f64 = 0.01;
const CONF_INHERENT_LOSS_UPPER_BOUND_OFFSET: f64 = 0.05;
const CONF_INHERENT_LOSS_UPPER_BOUND_BANDWIDTH_BALANCE: f64 = 75_000.0; // 75 kbps
const CONF_INHERENT_LOSS_UPPER_BOUND: f64 = 1.0e-3;
const CONF_NEWTON_ITERATIONS: usize = 3;
const CONF_NEWTON_STEP_SIZE: f64 = 3.0;
const CONF_USE_ACKED_BITRATE_ONLY_WHEN_OVERUSING: bool = false;
const CONF_NOT_INCREASE_IF_INHERENT_LOSS_LESS_THAN_AVERAGE_LOSS: bool = true;
const CONF_DELAYED_INCREASE_WINDOW: Duration = Duration::from_millis(1000);
const CONF_BANDWIDTH_RAMPUP_UPPER_BOUND_FACTOR: f64 = 1000000.0;
const CONF_PROBE_INTEGRATION_ENABLED: bool = false;
const CONF_CANDIDATE_FACTOR: [f64; 3] = [1.02, 1.0, 0.95];
const CONF_APPEND_ACKNOWLEDGED_RATE_CANDIDATE: bool = true;
const CONF_APPEND_DELAY_BASED_ESTIMATE_CANDIDATE: bool = true;
const CONF_BANDWIDTH_BACKOFF_LOWER_BOUND_FACTOR: f64 = 1.0;
const CONF_RAMPUP_ACCELERATION_MAXOUT_TIME: f64 = 60.0; // 60s
const CONF_RAMPUP_ACCELERATION_MAX_FACTOR: f64 = 0.0; // 60s
const CONF_HIGHER_BANDWIDTH_BIAS_FACTOR: f64 = 0.0002;
const CONF_HIGHER_LOG_BANDWIDTH_BIAS_FACTOR: f64 = 0.02;
const CONF_THRESHOLD_OF_HIGH_BANDWIDTH_PREFERENCE: f64 = 0.15;
const CONF_BANDWIDTH_PREFERENCE_SMOOTHING_FACTOR: f64 = 0.002;
const CONF_NOT_USE_ACKED_RATE_IN_ALR: bool = false;

struct LossController {
    state: LossControllerState,
    partial_observation: PartialObservation,
    last_send_time_most_recent_observation: SuperInstant,
    observations: Vec<Observation>,
    num_observations: u64,
    temporal_weights: Vec<f64>,
    instant_upper_bound_temporal_weights: Vec<f64>,
    cached_instant_upper_bound: Option<Bitrate>,
    last_time_estimate_reduced: SuperInstant,
    recovering_after_loss_timestamp: SuperInstant,
    bandwidth_limit_in_current_window: Bitrate,

    current_estimate: ChannelParameters,

    min_bitrate: Bitrate,
    max_bitrate: Bitrate,

    acknowledged_bitrate: Bitrate,

    delay_based_estimate: Bitrate,
    delay_detector_states: VecDeque<DelayDetectorBandwidthUsage>,
    probe_bitrate: Bitrate,
    upper_link_capacity: Bitrate,
    in_alr: bool,

    // output
    loss_based_results: Bitrate,
    _activated: bool,
    _is_ready: bool,
}

/// State of the Loss Controller
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum LossControllerState {
    /// LossController is in increasing state
    Increasing,
    /// LossController is in decreasing state
    Decreasing,
    /// LossController is in relaying the estimate of the delay controller
    DelayBased,
}

impl LossController {
    pub fn new() -> LossController {
        let mut controller = LossController {
            state: LossControllerState::DelayBased,
            partial_observation: PartialObservation::new(),
            last_send_time_most_recent_observation: SuperInstant::DistantFuture,
            observations: vec![Observation::DUMMY; CONF_OBSERVATION_WINDOW_SIZE],
            num_observations: 0,
            temporal_weights: vec![0_f64; CONF_OBSERVATION_WINDOW_SIZE],
            instant_upper_bound_temporal_weights: vec![0_f64; CONF_OBSERVATION_WINDOW_SIZE],
            cached_instant_upper_bound: None,
            last_time_estimate_reduced: SuperInstant::DistantPast,
            recovering_after_loss_timestamp: SuperInstant::DistantPast,
            bandwidth_limit_in_current_window: Bitrate::MAX,

            current_estimate: ChannelParameters::new(),

            min_bitrate: Bitrate::ZERO,
            max_bitrate: Bitrate::MAX,

            // review usage from here on after
            acknowledged_bitrate: Bitrate::ZERO,
            delay_based_estimate: Bitrate::ZERO,
            delay_detector_states: VecDeque::new(),
            probe_bitrate: Bitrate::MAX,
            upper_link_capacity: Bitrate::ZERO,
            in_alr: false,
            loss_based_results: Bitrate::ZERO,
            _activated: true,
            _is_ready: false,
        };

        controller.initialize_temporal_weights();

        controller
    }

    pub fn update_bandwidth_estimate(
        &mut self,
        packet_results: Vec<PacketResult>,
        delay_based_estimated: Bitrate,
        // TODO: not used ?
        // _acknowledged_bitrate: Bitrate,
        delay_detector_state: DelayDetectorBandwidthUsage,
        probe_bitrate: Option<Bitrate>,
        upper_link_capacity: Bitrate,
        in_alr: bool,
    ) {
        self.delay_based_estimate = delay_based_estimated;
        self.upper_link_capacity = upper_link_capacity;

        if !self._activated {
            debug!("the loss based controller is not enabled");
            return;
        }

        if let Some(probe_bitrate) = probe_bitrate {
            self.set_probe_bitrate(probe_bitrate);
        }

        if packet_results.is_empty() {
            debug!("packet results is empty");
            return;
        }

        if !self.maybe_add_observation(&packet_results, delay_detector_state) {
            return;
        }

        if !self.current_estimate.loss_limited_bandwidth.is_valid() {
            warn!("estimator must be initialized before use");
            return;
        }

        let mut best_candidate = self.current_estimate;
        let mut objective_max = f64::MIN;

        for candidate in self.get_candidates(in_alr).iter_mut() {
            self.newtons_method_update(candidate);

            let candidate_objective = self.get_objective(candidate);
            if candidate_objective > objective_max {
                objective_max = candidate_objective;
                best_candidate = *candidate;
            }
        }

        if best_candidate.loss_limited_bandwidth < self.current_estimate.loss_limited_bandwidth {
            self.last_time_estimate_reduced = self.last_send_time_most_recent_observation;
        }

        // do not increase the estimate if the average loss is greated than current inherent loss
        if self.get_average_reported_loss_ratio() > best_candidate.inherent_loss
            && CONF_NOT_INCREASE_IF_INHERENT_LOSS_LESS_THAN_AVERAGE_LOSS
            && self.current_estimate.loss_limited_bandwidth < best_candidate.loss_limited_bandwidth
        {
            best_candidate.loss_limited_bandwidth = self.current_estimate.loss_limited_bandwidth;
        }

        if self.is_bandwidth_limited_due_to_loss() {
            // Bound the estimate increase if:
            // 1. The estimate has been increased for less than
            // `delayed_increase_window` ago, and
            // 2. The best candidate is greater than bandwidth_limit_in_current_window.

            if self.recovering_after_loss_timestamp.is_finite()
                && self.recovering_after_loss_timestamp + CONF_DELAYED_INCREASE_WINDOW
                    > self.last_send_time_most_recent_observation
                && best_candidate.loss_limited_bandwidth > self.bandwidth_limit_in_current_window
            {
                best_candidate.loss_limited_bandwidth = self.bandwidth_limit_in_current_window;
            }

            let increase_when_loss_limited =
                self.is_estimate_increasing_when_loss_limited(best_candidate);

            if increase_when_loss_limited
                && self.probe_bitrate.is_valid()
                && self.acknowledged_bitrate.is_valid()
            {
                best_candidate.loss_limited_bandwidth =
                    if best_candidate.loss_limited_bandwidth.is_valid() {
                        best_candidate.loss_limited_bandwidth.as_f64().min(
                            CONF_BANDWIDTH_RAMPUP_UPPER_BOUND_FACTOR
                                * self.acknowledged_bitrate.as_f64(),
                        )
                    } else {
                        CONF_BANDWIDTH_RAMPUP_UPPER_BOUND_FACTOR
                            * self.acknowledged_bitrate.as_f64()
                    }
                    .into();

                self.recovering_after_loss_timestamp = self.last_send_time_most_recent_observation;
            }

            // Use probe bitrate as the estimate as probe bitrate is trusted to be
            // correct. After being used, the probe bitrate is reset.
            if CONF_PROBE_INTEGRATION_ENABLED && self.probe_bitrate.is_valid() {
                best_candidate.loss_limited_bandwidth = best_candidate
                    .loss_limited_bandwidth
                    .min(self.probe_bitrate);

                self.probe_bitrate = Bitrate::ZERO;
            }
        }

        let loss_limited_bandwidth = best_candidate.loss_limited_bandwidth;

        self.state = if self.is_estimate_increasing_when_loss_limited(best_candidate)
            && loss_limited_bandwidth < delay_based_estimated
        {
            LossControllerState::Increasing
        } else if loss_limited_bandwidth > self.delay_based_estimate {
            LossControllerState::Decreasing
        } else {
            // if loss_limited_bandwidth >= self.delay_based_estimated
            LossControllerState::DelayBased
        };

        self.current_estimate = best_candidate;

        const CONGESTION_CONTROLLER_MIN_BITRATE: f64 = 5000.0; // 5kbps
        const CONF_MAX_INCREASE_FACTOR: f64 = 1.3;

        if self.is_bandwidth_limited_due_to_loss()
            && (self.recovering_after_loss_timestamp.is_finite()
                || self.recovering_after_loss_timestamp + CONF_DELAYED_INCREASE_WINDOW
                    < self.last_send_time_most_recent_observation)
        {
            self.bandwidth_limit_in_current_window = CONGESTION_CONTROLLER_MIN_BITRATE
                .max(loss_limited_bandwidth.as_f64() * CONF_MAX_INCREASE_FACTOR)
                .into();

            self.recovering_after_loss_timestamp = self.last_send_time_most_recent_observation;
        }
    }

    fn is_estimate_increasing_when_loss_limited(&self, candidate: ChannelParameters) -> bool {
        if !self.is_bandwidth_limited_due_to_loss() {
            return false;
        }

        let current = self.current_estimate.loss_limited_bandwidth;
        let candidate = candidate.loss_limited_bandwidth;

        if current > candidate {
            return true;
        }

        current == candidate && self.state == LossControllerState::Increasing
    }

    fn is_bandwidth_limited_due_to_loss(&self) -> bool {
        self.state != LossControllerState::DelayBased
    }

    fn get_candidates(&self, in_alr: bool) -> Vec<ChannelParameters> {
        let mut bandwidths = vec![];

        let can_increase_bitrate = self.trendline_estimate_allow_bitrate_increase();
        let current = self.current_estimate.loss_limited_bandwidth;

        for factor in CONF_CANDIDATE_FACTOR.iter() {
            if !can_increase_bitrate && *factor > 1.0 {
                continue;
            }
            bandwidths.push(factor * current.as_f64());
        }

        if self.acknowledged_bitrate.is_valid()
            && CONF_APPEND_ACKNOWLEDGED_RATE_CANDIDATE
            && self.trendline_estimate_allow_emergency_backoff()
            && !CONF_NOT_USE_ACKED_RATE_IN_ALR
            && in_alr
        {
            bandwidths.push(
                self.acknowledged_bitrate.as_f64() * CONF_BANDWIDTH_BACKOFF_LOWER_BOUND_FACTOR,
            );
        }

        if self.delay_based_estimate.is_valid()
            && CONF_APPEND_DELAY_BASED_ESTIMATE_CANDIDATE
            && can_increase_bitrate
            && self.delay_based_estimate > current
        {
            bandwidths.push(self.delay_based_estimate.as_f64());
        }

        let candidate_bandwidth_upper_bound = self.get_candidate_bandwidth_upper_bound().as_f64();

        let mut candidates = Vec::with_capacity(bandwidths.len());

        for bandwidth in bandwidths.iter_mut() {
            let mut candidate = self.current_estimate;
            candidate.loss_limited_bandwidth = if CONF_TRENDLINE_INTEGRATION_ENABLED {
                bandwidth.min(candidate_bandwidth_upper_bound).into()
            } else {
                bandwidth
                    .min(
                        self.current_estimate
                            .loss_limited_bandwidth
                            .as_f64()
                            .max(candidate_bandwidth_upper_bound),
                    )
                    .into()
            };
            candidate.inherent_loss = self.get_feasible_inherent_loss(&candidate);
            candidates.push(candidate);
        }

        candidates
    }

    fn get_candidate_bandwidth_upper_bound(&self) -> Bitrate {
        let mut upper_bound = self.max_bitrate;
        if self.is_bandwidth_limited_due_to_loss()
            && self.bandwidth_limit_in_current_window.is_valid()
        {
            upper_bound = self.bandwidth_limit_in_current_window;
        }

        if CONF_TRENDLINE_INTEGRATION_ENABLED {
            upper_bound = self.get_instant_upper_bound().min(upper_bound);
            if self.delay_based_estimate.is_valid() {
                upper_bound = upper_bound.min(self.delay_based_estimate);
            }
        }

        if !self.acknowledged_bitrate.is_valid() {
            return upper_bound;
        }

        if CONF_RAMPUP_ACCELERATION_MAX_FACTOR > 0.0 {
            if let (Some(most_recent), Some(reduced)) = (
                self.last_send_time_most_recent_observation.as_instant(),
                self.last_time_estimate_reduced.as_instant(),
            ) {
                let delta = most_recent - reduced;
                let time_since_bw_reduced = CONF_RAMPUP_ACCELERATION_MAXOUT_TIME
                    .min(delta.max(Duration::ZERO).as_secs_f64());

                let rampup_acceleration = CONF_RAMPUP_ACCELERATION_MAX_FACTOR
                    * time_since_bw_reduced
                    / CONF_RAMPUP_ACCELERATION_MAXOUT_TIME;

                upper_bound = (upper_bound.as_f64()
                    + rampup_acceleration * self.acknowledged_bitrate.as_f64())
                .into();
            }
        }

        upper_bound
    }

    fn get_average_reported_loss_ratio(&self) -> f64 {
        if self.num_observations == 0 {
            return 0.0;
        }

        let mut num_packets = 0.0;
        let mut num_lost_packets = 0.0;

        for observation in self.observations.iter() {
            if !observation.is_initialized {
                continue;
            }
            let index = (self.num_observations - 1) - observation.id;
            let instant_temporal_weight = self.instant_upper_bound_temporal_weights[index as usize];
            num_packets += instant_temporal_weight * observation.num_packets as f64;
            num_lost_packets += instant_temporal_weight * observation.num_lost_packets as f64;
        }

        num_lost_packets / num_packets
    }

    fn get_objective(&self, candidate: &ChannelParameters) -> f64 {
        let mut objective = 0.0;
        let high_bandwidth_bias = self.get_high_bandwidth_bias(candidate.loss_limited_bandwidth);

        for observation in self.observations.iter() {
            if !observation.is_initialized {
                continue;
            }

            let loss_probability = self.get_loss_probability(
                candidate.inherent_loss,
                candidate.loss_limited_bandwidth,
                observation.sending_rate,
            );

            let index = (self.num_observations - 1) - observation.id;
            let temporal_weight = self.temporal_weights[index as usize];

            objective += temporal_weight
                * (observation.num_lost_packets as f64 * f64::log10(loss_probability)
                    + (observation.num_received_packets as f64
                        * f64::log10(1.0 - loss_probability)));

            objective += temporal_weight * high_bandwidth_bias * observation.num_packets as f64;
        }

        objective
    }

    fn get_high_bandwidth_bias(&self, bandwidth: Bitrate) -> f64 {
        if !bandwidth.is_valid() {
            return 0.0;
        }

        let average_reported_loss_ratio = self.get_average_reported_loss_ratio();

        self.adjust_bias_factor(
            average_reported_loss_ratio,
            CONF_HIGHER_BANDWIDTH_BIAS_FACTOR,
        ) * bandwidth.as_f64()
            + self.adjust_bias_factor(
                average_reported_loss_ratio,
                CONF_HIGHER_LOG_BANDWIDTH_BIAS_FACTOR,
            ) * f64::log10(1.0 + bandwidth.as_f64())
    }

    fn adjust_bias_factor(&self, loss_rate: f64, bias_factor: f64) -> f64 {
        let diff = CONF_THRESHOLD_OF_HIGH_BANDWIDTH_PREFERENCE - loss_rate;
        bias_factor * (diff / CONF_BANDWIDTH_PREFERENCE_SMOOTHING_FACTOR + diff.abs())
    }

    fn maybe_add_observation(
        &mut self,
        packet_results: &[PacketResult],
        delay_detector_state: DelayDetectorBandwidthUsage,
    ) -> bool {
        self.delay_detector_states.push_front(delay_detector_state);
        if self.delay_detector_states.len() > CONF_TRENDLINE_OBSERVATIONS_WINDOW_SIZE {
            self.delay_detector_states.pop_back();
        }

        let Some(summary) = PacketResultsSummary::from(packet_results) else {
            return false;
        };

        let last_send_time = summary.last_send_time;

        self.partial_observation.update(summary);

        if !self.last_send_time_most_recent_observation.is_finite() {
            self.last_send_time_most_recent_observation = last_send_time.into();
        }

        let observation_duration = last_send_time
            - self
                .last_send_time_most_recent_observation
                .as_instant()
                .expect("instant is not finite");

        if observation_duration <= Duration::ZERO {
            return false;
        }

        // decide if we can accept the partial observation as complete

        let too_small = observation_duration <= CONF_OBSERVATION_DURATION_LOWER_BOUND;
        let overusing = delay_detector_state == DelayDetectorBandwidthUsage::Overusing;
        if too_small && (overusing || !CONF_TRENDLINE_INTEGRATION_ENABLED) {
            return false;
        }

        self.last_send_time_most_recent_observation = last_send_time.into();

        let observation = {
            let id = self.num_observations % CONF_OBSERVATION_WINDOW_SIZE as u64;
            self.num_observations += 1;
            Observation::with(&self.partial_observation, id)
        };

        // save our complete observation
        self.observations
            .insert(observation.id as usize, observation);

        // renew the partial observation
        self.partial_observation = PartialObservation::new();

        // calculate upper bound
        self.cached_instant_upper_bound = Some(self.calculate_instant_upper_bound());

        true
    }

    pub fn set_max_bitrate(&mut self, max_bitrate: Bitrate) {
        self.max_bitrate = max_bitrate;
    }

    pub fn set_min_bitrate(&mut self, min_bitrate: Bitrate) {
        self.min_bitrate = min_bitrate;
    }

    pub fn set_probe_bitrate(&mut self, probe_bitrate: Bitrate) {
        if probe_bitrate.is_valid() && self.probe_bitrate > probe_bitrate {
            self.probe_bitrate = probe_bitrate;
        }
    }

    pub fn set_bandwidth_estimate(&mut self, bandwidth_estimate: Bitrate) {
        self.current_estimate.loss_limited_bandwidth = bandwidth_estimate;
    }

    pub fn set_acknowledged_bitrate(&mut self, acknowledged_bitrate: Bitrate) {
        self.acknowledged_bitrate = acknowledged_bitrate;
    }

    pub fn get_loss_based_result(&self) -> LossBasedBweResult {
        let mut result = LossBasedBweResult {
            bandwidth_estimate: self.current_estimate.loss_limited_bandwidth.as_valid(),
            state: self.state,
        };

        if self.num_observations == 0 {
            return result;
        }

        let Some(loss_limited_bandwidth) = self.current_estimate.loss_limited_bandwidth.as_valid() else {
            return result
        };

        if self.delay_based_estimate.is_valid() {
            result.bandwidth_estimate = Some(
                loss_limited_bandwidth
                    .min(self.delay_based_estimate)
                    .min(self.get_instant_upper_bound()),
            )
        } else {
            result.bandwidth_estimate =
                Some(loss_limited_bandwidth.min(self.get_instant_upper_bound()))
        }

        result
    }

    fn calculate_instant_upper_bound(&mut self) -> Bitrate {
        // this requires someone to set the max bitrate from outside
        let mut instant_limit = self.max_bitrate;

        let average_reported_loss_ratio = self.average_reported_loss_ratio();

        if average_reported_loss_ratio > CONF_INSTANT_UPPER_BOUND_LOSS_OFFSET {
            instant_limit = Bitrate::from(
                CONF_INSTANT_UPPER_BOUND_BANDWIDTH_BALANCE
                    / (average_reported_loss_ratio - CONF_INSTANT_UPPER_BOUND_LOSS_OFFSET),
            );

            if average_reported_loss_ratio > CONF_HIGH_LOSS_RATE_THRESHOLD {
                let limit = CONF_BANDTIDTH_CAP_AT_HIGH_LOSS_RATE
                    - CONF_SLOPE_OF_BWE_HIGH_LOSS_FUNCTION * average_reported_loss_ratio;

                let min = self.min_bitrate.as_f64();

                instant_limit = Bitrate::from(limit.max(min));
            }
        }

        let is_bw_limited_due_to_loss = self.state != LossControllerState::DelayBased;
        if is_bw_limited_due_to_loss {
            // and if self.upper_link_capacity.is_valid()
            // and if conf.bound_by_upper_link_capacity_when_loss_limited
            instant_limit = instant_limit.min(self.upper_link_capacity);
        }

        instant_limit
    }

    fn get_instant_upper_bound(&self) -> Bitrate {
        self.cached_instant_upper_bound
            .as_valid()
            .unwrap_or(self.max_bitrate)
    }

    fn average_reported_loss_ratio(&self) -> f64 {
        let mut num_packets = 0_f64;
        let mut num_lost_packets = 0_f64;

        for observation in self.observations.iter() {
            if !observation.is_initialized {
                continue;
            }

            let index = (self.num_observations - 1) - observation.id;

            let instant_temporal_weight = self
                .instant_upper_bound_temporal_weights
                .get(index as usize)
                .expect("instant temporal weight: index out of bounds");

            num_packets += instant_temporal_weight * observation.num_packets as f64;
            num_lost_packets += instant_temporal_weight * observation.num_lost_packets as f64;
        }

        num_lost_packets / num_packets
    }

    fn newtons_method_update(&self, channel_parameters: &mut ChannelParameters) {
        if self.num_observations == 0 {
            return;
        }

        for _ in 0..CONF_NEWTON_ITERATIONS {
            let derivatives = self.get_derivatives(channel_parameters);
            channel_parameters.inherent_loss -= CONF_NEWTON_STEP_SIZE / derivatives.1;
            channel_parameters.inherent_loss = self.get_feasible_inherent_loss(channel_parameters);
        }
    }

    fn get_derivatives(&self, channel_prameters: &ChannelParameters) -> (f64, f64) {
        let mut derivatives: (f64, f64) = (0.0, 0.0);

        for observation in &self.observations {
            if !observation.is_initialized {
                continue;
            }

            let loss_probability = self.get_loss_probability(
                channel_prameters.inherent_loss,
                channel_prameters.loss_limited_bandwidth,
                observation.sending_rate,
            );

            let index = (self.num_observations - 1) - observation.id;
            let temporal_weight = self
                .temporal_weights
                .get(index as usize)
                .expect("temporal weight: index out of bounds");

            derivatives.0 += temporal_weight
                * ((observation.num_lost_packets as f64 / loss_probability)
                    - (observation.num_received_packets as f64 / (1.0 - loss_probability)));

            derivatives.1 -= temporal_weight
                * ((observation.num_lost_packets as f64 / f64::powi(loss_probability, 2))
                    + (observation.num_received_packets as f64
                        / f64::powi(1.0 - loss_probability, 2)));
        }

        if derivatives.1 >= 0.0 {
            assert!(
                false,
                "the second derivative is mathematically guaranteed to be negative"
            );
            // if this happens consider clamping to -1.0e-6 as goog-webrtc does
        }

        derivatives
    }

    fn get_loss_probability(
        &self,
        inherent_loss: f64,
        loss_limited_bandwidth: Bitrate,
        sending_rate: Bitrate,
    ) -> f64 {
        let inherent_loss = inherent_loss.clamp(0.0, 1.0);

        // maybe warn if sending rate or loss limited bandwidth are not finite

        let mut loss_probability = inherent_loss;
        if sending_rate.is_valid()
            && loss_limited_bandwidth.is_valid()
            && sending_rate > loss_limited_bandwidth
        {
            loss_probability += (1.0 - inherent_loss)
                * (sending_rate.as_f64() - loss_limited_bandwidth.as_f64())
                / sending_rate.as_f64();
        }

        loss_probability.max(10e-6).min(1.0 - 1.0e-6)
    }

    fn get_feasible_inherent_loss(&self, channel_parameters: &ChannelParameters) -> f64 {
        channel_parameters
            .inherent_loss
            .max(CONF_INHERENT_LOSS_UPPER_BOUND)
            .min(
                self.get_inherent_loss_upper_bound(Some(channel_parameters.loss_limited_bandwidth)),
            )
    }

    fn get_inherent_loss_upper_bound(&self, bandwidth: Option<Bitrate>) -> f64 {
        let Some(bandwidth) = bandwidth else {
            return 1.0
        };

        if bandwidth == Bitrate::ZERO {
            return 1.0;
        }

        let inherent_loss_upper_bound = CONF_INHERENT_LOSS_UPPER_BOUND_OFFSET
            + CONF_INHERENT_LOSS_UPPER_BOUND_BANDWIDTH_BALANCE / bandwidth.as_f64();

        inherent_loss_upper_bound.min(1.0)
    }

    // TODO: the following two fns could be encapsulated in a struct for managing the delay detector states
    fn trendline_estimate_allow_bitrate_increase(&self) -> bool {
        if !CONF_TRENDLINE_INTEGRATION_ENABLED {
            return true;
        }

        for state in self.delay_detector_states.iter() {
            if *state == DelayDetectorBandwidthUsage::Overusing
                || *state == DelayDetectorBandwidthUsage::Underusing
            {
                return false;
            }
        }

        true
    }

    fn trendline_estimate_allow_emergency_backoff(&self) -> bool {
        if !CONF_TRENDLINE_INTEGRATION_ENABLED {
            return true;
        }

        if !CONF_USE_ACKED_BITRATE_ONLY_WHEN_OVERUSING {
            return true;
        }

        // TODO: consider passing this in as params
        for state in self.delay_detector_states.iter() {
            if *state == DelayDetectorBandwidthUsage::Overusing {
                return true;
            }
        }

        false
    }

    fn is_bw_limited_due_to_loss(&self) -> bool {
        self.state != LossControllerState::DelayBased
    }

    fn initialize_temporal_weights(&mut self) {
        for i in 0..CONF_OBSERVATION_WINDOW_SIZE {
            let val = f64::powi(CONF_TEMPORAL_WEIGHT_FACTOR, i as i32);
            self.temporal_weights.insert(i, val);
            let val = f64::powi(CONF_INSTANT_UPPER_BOUND_TEMPORAL_WEIGHT_FACTOR, i as i32);
            self.instant_upper_bound_temporal_weights.insert(i, val);
        }
    }
}

struct PacketResultsSummary {
    num_packets: u64,
    num_lost_packets: u64,
    total_size: u64,
    first_send_time: Instant,
    last_send_time: Instant,
}

impl PacketResultsSummary {
    pub fn new(first_send_time: Instant, last_send_time: Instant) -> PacketResultsSummary {
        PacketResultsSummary {
            num_packets: 0,
            num_lost_packets: 0,
            total_size: 0,
            last_send_time,
            first_send_time,
        }
    }

    pub fn from(packet_results: &[PacketResult]) -> Option<PacketResultsSummary> {
        let first = packet_results.first()?;

        let mut summary = PacketResultsSummary::new(first.first_send_time, first.first_send_time);
        for packet in packet_results.iter() {
            summary.num_packets += 1;
            summary.total_size += packet.size.as_bytes_usize() as u64;
            summary.first_send_time = min(summary.first_send_time, packet.first_send_time);
            summary.last_send_time = max(summary.last_send_time, packet.first_send_time);
            if packet.receive_time.is_none() {
                summary.num_lost_packets += 1;
            }
        }

        Some(summary)
    }
}

#[derive(Debug, Clone, Copy)]
struct Observation {
    num_packets: u64,
    num_lost_packets: u64,
    num_received_packets: u64,
    sending_rate: Bitrate,
    id: u64,
    is_initialized: bool,
}

impl Observation {
    pub const DUMMY: Self = Self {
        num_packets: 0,
        num_lost_packets: 0,
        num_received_packets: 0,
        sending_rate: Bitrate::ZERO,
        id: 0,
        is_initialized: false,
    };

    pub fn with(partial_observation: &PartialObservation, id: u64) -> Observation {
        Observation {
            num_packets: partial_observation.num_packets,
            num_lost_packets: partial_observation.num_lost_packets,
            num_received_packets: partial_observation.num_packets
                - partial_observation.num_lost_packets,
            sending_rate: Bitrate::from(partial_observation.size as f64 / 1.0),
            id,
            is_initialized: true,
        }
    }
}

struct PartialObservation {
    num_packets: u64,
    num_lost_packets: u64,
    size: u64,
}

impl PartialObservation {
    pub fn new() -> PartialObservation {
        PartialObservation {
            num_packets: 0,
            num_lost_packets: 0,
            size: 0,
        }
    }

    pub fn update(&mut self, summary: PacketResultsSummary) {
        // TODO: figure out whether to use usize or u64
        self.num_packets += summary.num_packets;
        self.num_lost_packets += summary.num_lost_packets;
        self.size += summary.total_size;
    }
}

#[derive(Debug, Clone, Copy)]
struct ChannelParameters {
    inherent_loss: f64,
    loss_limited_bandwidth: Bitrate,
}

impl ChannelParameters {
    pub fn new() -> ChannelParameters {
        ChannelParameters {
            inherent_loss: 0.0,
            loss_limited_bandwidth: Bitrate::ZERO,
        }
    }
}

trait AsValid<T> {
    fn as_valid(&self) -> Option<T>;
    fn is_valid(&self) -> bool;
}

impl AsValid<Bitrate> for Option<Bitrate> {
    fn as_valid(&self) -> Option<Bitrate> {
        if let Some(bitrate) = self {
            if bitrate.as_f64().is_finite() {
                return Some(*bitrate);
            }
        }
        None
    }

    fn is_valid(&self) -> bool {
        self.as_valid().is_some()
    }
}

// TODO: should Bitrate::MAX be considered invalid?
impl AsValid<Bitrate> for Bitrate {
    fn as_valid(&self) -> Option<Bitrate> {
        if self.as_f64().is_finite() {
            return Some(*self);
        }
        None
    }

    fn is_valid(&self) -> bool {
        self.as_valid().is_some()
    }
}

struct LossBasedBweResult {
    bandwidth_estimate: Option<Bitrate>,
    state: LossControllerState,
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use systemstat::Duration;

    use crate::rtp::{Bitrate, DataSize};

    use super::{
        LossBasedBweResult, LossController, PacketResult, CONF_OBSERVATION_DURATION_LOWER_BOUND,
    };

    fn create_packet_results_with_received_packets(first_ts: Instant) -> Vec<PacketResult> {
        let small = Duration::from_millis(200);
        let mut result: Vec<PacketResult> = Vec::new();

        for i in 0..3 {
            result.push(PacketResult {
                receive_time: Some(first_ts + small + small * i),
                first_send_time: first_ts + (small * i),
                size: DataSize::bytes(15_000),
            })
        }

        result
    }

    #[test]
    fn generic_test() {
        let mut lbc = LossController::new();
        lbc.set_min_bitrate(Bitrate::from(50_000)); // 50 kbps
        lbc.set_max_bitrate(Bitrate::from(1_000_000_000)); // 1 Gbps

        let acknowledged_bitrate = Bitrate::from(1_000_000); // 1 Mbps
        lbc.set_acknowledged_bitrate(acknowledged_bitrate);

        let result = create_packet_results_with_received_packets(Instant::now());
        lbc.update_bandwidth_estimate(
            result,
            acknowledged_bitrate,
            // acknowledged_bitrate,
            super::DelayDetectorBandwidthUsage::Underusing,
            None,
            acknowledged_bitrate,
            false,
        );

        let result = create_packet_results_with_received_packets(Instant::now());
        lbc.update_bandwidth_estimate(
            result,
            acknowledged_bitrate,
            // acknowledged_bitrate,
            super::DelayDetectorBandwidthUsage::Underusing,
            None,
            acknowledged_bitrate,
            false,
        );
        let result = create_packet_results_with_received_packets(Instant::now());
        lbc.update_bandwidth_estimate(
            result,
            acknowledged_bitrate,
            // acknowledged_bitrate,
            super::DelayDetectorBandwidthUsage::Underusing,
            None,
            acknowledged_bitrate,
            false,
        );

        let LossBasedBweResult {
            bandwidth_estimate,
            state,
        } = lbc.get_loss_based_result();

        println!("{:?} {:?}", bandwidth_estimate, state);
    }
}
