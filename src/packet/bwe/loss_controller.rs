#![allow(dead_code)]
// ^- TODO: remove

// ref: https://webrtc.googlesource.com/src/+/14e2779a6ccdc67038ed2069a5732dd41617c6f0/modules/congestion_controller/goog_cc/loss_based_bwe_v2.cc

use std::cmp::max;
use std::cmp::min;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::rtp_::TwccSendRecord;
use crate::{Bitrate, DataSize};

use super::super_instant::SuperInstant;
use super::BandwidthUsage;

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

pub struct LossController {
    /// Configuration for the controller
    config: Config,

    /// The current state of the controller
    state: LossControllerState,

    /// Staging ground for observations while they are being constructed
    partial_observation: PartialObservation,

    /// The last packet sent in the most recent observation.
    last_send_time_most_recent_observation: SuperInstant,

    /// Window of observations
    observations: Box<[Observation]>,

    /// Forever growing counter of observations. Observation::id derives from this
    num_observations: u64,
    /// Temporal weights, used to weight observations by recency. Same size as `observations`
    temporal_weights: Box<[f64]>,

    /// Upper bound temporal weights, used to weight observations by recency. Same size as `observations`
    instant_upper_bound_temporal_weights: Box<[f64]>,

    /// ?
    cached_instant_upper_bound: Option<Bitrate>,
    /// Last time we reduced the estimate
    last_time_estimate_reduced: SuperInstant,
    /// When we started recovering after loss last time?
    recovering_after_loss_timestamp: SuperInstant,

    /// ?
    bandwidth_limit_in_current_window: Bitrate,

    /// The current estimate
    current_estimate: ChannelParameters,

    /// The min bitrate we will emit as an estimate
    min_bitrate: Bitrate,
    /// The max bitrate we will emit as an estimate
    max_bitrate: Bitrate,

    /// The most recent acknowledged bitrate derived from TWCC
    acknowledged_bitrate: Bitrate,

    /// The estimated bitrate derived from the delay based estimator
    delay_based_estimate: Bitrate,

    /// Prior states from the delay based estimator
    delay_detector_states: VecDeque<BandwidthUsage>,

    // output
    loss_based_results: Bitrate,
    _activated: bool,
    _is_ready: bool,
    //
    // NB: Not ported from goog_cc(ALR, probing, link capcity)
}

struct Config {
    observation_window_size: usize, // minimum is 2
    observation_duration_lower_bound: Duration,
    trendline_integration_enabled: bool,
    trendline_observations_window_size: usize,
    temporal_weight_factor: f64,
    instant_upper_bound_temporal_weight_factor: f64,
    instant_upper_bound_loss_offset: f64,
    instant_upper_bound_bandwidth_balance: f64,
    high_loss_rate_threshold: f64,
    slope_of_bwe_high_loss_function: f64,
    bandtidth_cap_at_high_loss_rate: f64,
    initial_inherent_loss_estimate: f64,
    inherent_loss_upper_bound_offset: f64,
    inherent_loss_upper_bound_bandwidth_balance: f64,
    inherent_loss_upper_bound: f64,
    newton_iterations: usize,
    newton_step_size: f64,
    use_acked_bitrate_only_when_overusing: bool,
    not_increase_if_inherent_loss_less_than_average_loss: bool,
    delayed_increase_window: Duration,
    bandwidth_rampup_upper_bound_factor: f64,
    probe_integration_enabled: bool,
    candidate_factor: [f64; 3],
    append_acknowledged_rate_candidate: bool,
    append_delay_based_estimate_candidate: bool,
    bandwidth_backoff_lower_bound_factor: f64,
    rampup_acceleration_maxout_time: f64,
    rampup_acceleration_max_factor: f64,
    higher_bandwidth_bias_factor: f64,
    higher_log_bandwidth_bias_factor: f64,
    threshold_of_high_bandwidth_preference: f64,
    bandwidth_preference_smoothing_factor: f64,
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
        let config = Config::default();

        let mut controller = LossController {
            state: LossControllerState::DelayBased,
            partial_observation: PartialObservation::new(),
            last_send_time_most_recent_observation: SuperInstant::DistantFuture,
            observations: vec![Observation::DUMMY; config.observation_window_size]
                .into_boxed_slice(),
            num_observations: 0,
            temporal_weights: vec![0_f64; config.observation_window_size].into_boxed_slice(),
            instant_upper_bound_temporal_weights: vec![0_f64; config.observation_window_size]
                .into_boxed_slice(),
            cached_instant_upper_bound: None,
            last_time_estimate_reduced: SuperInstant::DistantPast,
            recovering_after_loss_timestamp: SuperInstant::DistantPast,
            bandwidth_limit_in_current_window: Bitrate::MAX,

            current_estimate: ChannelParameters::new(),

            min_bitrate: Bitrate::kbps(1),
            max_bitrate: Bitrate::INFINITY,

            // review usage from here on after
            acknowledged_bitrate: Bitrate::INFINITY,
            delay_based_estimate: Bitrate::INFINITY,
            delay_detector_states: VecDeque::new(),
            loss_based_results: Bitrate::ZERO,
            _activated: true,
            _is_ready: false,

            config,
        };

        controller.initialize_temporal_weights();

        controller
    }

    pub fn update_bandwidth_estimate(
        &mut self,
        packet_results: &[TwccSendRecord],
        delay_based_estimated: Bitrate,
        // TODO: not used ?
        // _acknowledged_bitrate: Bitrate,
        delay_detector_state: BandwidthUsage,
    ) {
        self.delay_based_estimate = delay_based_estimated;

        if !self._activated {
            debug!("the loss based controller is not enabled");
            return;
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

        for candidate in self.get_candidates().iter_mut() {
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

        // do not increase the estimate if the average loss is greater than current inherent loss
        if self.get_average_reported_loss_ratio() > best_candidate.inherent_loss
            && self
                .config
                .not_increase_if_inherent_loss_less_than_average_loss
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
                && self.recovering_after_loss_timestamp + self.config.delayed_increase_window
                    > self.last_send_time_most_recent_observation
                && best_candidate.loss_limited_bandwidth > self.bandwidth_limit_in_current_window
            {
                best_candidate.loss_limited_bandwidth = self.bandwidth_limit_in_current_window;
            }

            let increase_when_loss_limited =
                self.is_estimate_increasing_when_loss_limited(best_candidate);

            if increase_when_loss_limited
                // TODO: Keep this despite not having a probe bitrate?
                // && self.probe_bitrate.is_valid()
                && self.acknowledged_bitrate.is_valid()
            {
                best_candidate.loss_limited_bandwidth =
                    if best_candidate.loss_limited_bandwidth.is_valid() {
                        best_candidate.loss_limited_bandwidth.as_f64().min(
                            self.config.bandwidth_rampup_upper_bound_factor
                                * self.acknowledged_bitrate.as_f64(),
                        )
                    } else {
                        self.config.bandwidth_rampup_upper_bound_factor
                            * self.acknowledged_bitrate.as_f64()
                    }
                    .into();

                self.recovering_after_loss_timestamp = self.last_send_time_most_recent_observation;
            }
        }

        let loss_limited_bandwidth = best_candidate.loss_limited_bandwidth;

        let new_state = if self.is_estimate_increasing_when_loss_limited(best_candidate)
            && loss_limited_bandwidth < delay_based_estimated
        {
            LossControllerState::Increasing
        } else if loss_limited_bandwidth < self.delay_based_estimate {
            LossControllerState::Decreasing
        } else {
            // if loss_limited_bandwidth >= self.delay_based_estimated
            LossControllerState::DelayBased
        };
        self.set_state(new_state);

        self.current_estimate = best_candidate;

        const CONGESTION_CONTROLLER_MIN_BITRATE: f64 = 5000.0; // 5kbps
        const CONF_MAX_INCREASE_FACTOR: f64 = 1.3;

        if self.is_bandwidth_limited_due_to_loss()
            && (self.recovering_after_loss_timestamp.is_finite()
                || self.recovering_after_loss_timestamp + self.config.delayed_increase_window
                    < self.last_send_time_most_recent_observation)
        {
            self.bandwidth_limit_in_current_window = CONGESTION_CONTROLLER_MIN_BITRATE
                .max(loss_limited_bandwidth.as_f64() * CONF_MAX_INCREASE_FACTOR)
                .into();

            self.recovering_after_loss_timestamp = self.last_send_time_most_recent_observation;
        }
        dbg!(self.current_estimate);
    }

    fn is_estimate_increasing_when_loss_limited(&self, candidate: ChannelParameters) -> bool {
        if !self.is_bandwidth_limited_due_to_loss() {
            return false;
        }

        let current = self.current_estimate.loss_limited_bandwidth;
        let candidate = candidate.loss_limited_bandwidth;

        if current < candidate {
            return true;
        }

        current == candidate && self.state == LossControllerState::Increasing
    }

    fn is_bandwidth_limited_due_to_loss(&self) -> bool {
        self.state != LossControllerState::DelayBased
    }

    fn get_candidates(&self) -> Vec<ChannelParameters> {
        let mut bandwidths = vec![];

        let can_increase_bitrate = self.trendline_estimate_allow_bitrate_increase();
        let current = self.current_estimate.loss_limited_bandwidth;

        for factor in self.config.candidate_factor.iter() {
            if !can_increase_bitrate && *factor > 1.0 {
                continue;
            }
            bandwidths.push(factor * current.as_f64());
        }

        if self.delay_based_estimate.is_valid()
            && self.config.append_delay_based_estimate_candidate
            && can_increase_bitrate
            && self.delay_based_estimate > current
        {
            bandwidths.push(self.delay_based_estimate.as_f64());
        }

        let candidate_bandwidth_upper_bound = self.get_candidate_bandwidth_upper_bound().as_f64();

        let mut candidates = Vec::with_capacity(bandwidths.len());

        for bandwidth in bandwidths.iter_mut() {
            let mut candidate = self.current_estimate;
            candidate.loss_limited_bandwidth = if self.config.trendline_integration_enabled {
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

        if self.config.trendline_integration_enabled {
            upper_bound = self.get_instant_upper_bound().min(upper_bound);
            if self.delay_based_estimate.is_valid() {
                upper_bound = upper_bound.min(self.delay_based_estimate);
            }
        }

        if !self.acknowledged_bitrate.is_valid() {
            return upper_bound;
        }

        if self.config.rampup_acceleration_max_factor > 0.0 {
            if let (Some(most_recent), Some(reduced)) = (
                self.last_send_time_most_recent_observation.as_instant(),
                self.last_time_estimate_reduced.as_instant(),
            ) {
                let delta = most_recent - reduced;
                let time_since_bw_reduced = self
                    .config
                    .rampup_acceleration_maxout_time
                    .min(delta.max(Duration::ZERO).as_secs_f64());

                let rampup_acceleration = self.config.rampup_acceleration_max_factor
                    * time_since_bw_reduced
                    / self.config.rampup_acceleration_maxout_time;

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
                * (observation.num_lost_packets as f64 * f64::ln(loss_probability)
                    + (observation.num_received_packets as f64 * f64::ln(1.0 - loss_probability)));

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
            self.config.higher_bandwidth_bias_factor,
        ) * bandwidth.as_f64()
            + self.adjust_bias_factor(
                average_reported_loss_ratio,
                self.config.higher_log_bandwidth_bias_factor,
            ) * f64::ln(1.0 + bandwidth.as_f64())
    }

    fn adjust_bias_factor(&self, loss_rate: f64, bias_factor: f64) -> f64 {
        let diff = self.config.threshold_of_high_bandwidth_preference - loss_rate;
        bias_factor * (diff / self.config.bandwidth_preference_smoothing_factor + diff.abs())
    }

    fn maybe_add_observation(
        &mut self,
        packet_results: &[TwccSendRecord],
        delay_detector_state: BandwidthUsage,
    ) -> bool {
        self.delay_detector_states.push_front(delay_detector_state);
        if self.delay_detector_states.len() > self.config.trendline_observations_window_size {
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

        let too_small = observation_duration <= self.config.observation_duration_lower_bound;
        let overusing = delay_detector_state == BandwidthUsage::Overuse;
        if too_small && (overusing || !self.config.trendline_integration_enabled) {
            return false;
        }

        self.last_send_time_most_recent_observation = last_send_time.into();

        let observation = {
            let id = self.num_observations;
            self.num_observations += 1;

            Observation::with(&self.partial_observation, id)
        };

        // save our complete observation
        self.observations[observation.id as usize % self.config.observation_window_size] =
            observation;

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

        let Some(loss_limited_bandwidth) = self.current_estimate.loss_limited_bandwidth.as_valid()
        else {
            return result;
        };
        let instant_upper_bound = self.get_instant_upper_bound();
        dbg!(
            loss_limited_bandwidth,
            self.delay_based_estimate,
            instant_upper_bound
        );

        if self.delay_based_estimate.is_valid() {
            result.bandwidth_estimate = Some(
                loss_limited_bandwidth
                    .min(self.delay_based_estimate)
                    .min(instant_upper_bound),
            )
        } else {
            result.bandwidth_estimate = Some(loss_limited_bandwidth.min(instant_upper_bound))
        }

        result
    }

    fn calculate_instant_upper_bound(&mut self) -> Bitrate {
        // this requires someone to set the max bitrate from outside
        let mut instant_limit = self.max_bitrate;

        let average_reported_loss_ratio = self.average_reported_loss_ratio();

        if average_reported_loss_ratio > self.config.instant_upper_bound_loss_offset {
            instant_limit = Bitrate::from(
                self.config.instant_upper_bound_bandwidth_balance
                    / (average_reported_loss_ratio - self.config.instant_upper_bound_loss_offset),
            );

            if average_reported_loss_ratio > self.config.high_loss_rate_threshold {
                let limit = self.config.bandtidth_cap_at_high_loss_rate
                    - self.config.slope_of_bwe_high_loss_function * average_reported_loss_ratio;

                let min = self.min_bitrate.as_f64();

                instant_limit = Bitrate::from(limit.max(min));
            }
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

        for _ in 0..self.config.newton_iterations {
            let derivatives = self.get_derivatives(channel_parameters);
            channel_parameters.inherent_loss -=
                self.config.newton_step_size * (derivatives.0 / derivatives.1);
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

        loss_probability.max(1.0e-6).min(1.0 - 1.0e-6)
    }

    fn get_feasible_inherent_loss(&self, channel_parameters: &ChannelParameters) -> f64 {
        channel_parameters
            .inherent_loss
            .max(self.config.inherent_loss_upper_bound)
            .min(
                self.get_inherent_loss_upper_bound(Some(channel_parameters.loss_limited_bandwidth)),
            )
    }

    fn get_inherent_loss_upper_bound(&self, bandwidth: Option<Bitrate>) -> f64 {
        let Some(bandwidth) = bandwidth else {
            return 1.0;
        };

        if bandwidth == Bitrate::ZERO {
            return 1.0;
        }

        let inherent_loss_upper_bound = self.config.inherent_loss_upper_bound_offset
            + self.config.inherent_loss_upper_bound_bandwidth_balance / bandwidth.as_f64();

        inherent_loss_upper_bound.min(1.0)
    }

    // TODO: the following two fns could be encapsulated in a struct for managing the delay detector states
    fn trendline_estimate_allow_bitrate_increase(&self) -> bool {
        if !self.config.trendline_integration_enabled {
            return true;
        }

        for state in self.delay_detector_states.iter() {
            if *state == BandwidthUsage::Overuse || *state == BandwidthUsage::Underuse {
                return false;
            }
        }

        true
    }

    fn trendline_estimate_allow_emergency_backoff(&self) -> bool {
        if !self.config.trendline_integration_enabled {
            return true;
        }

        if !self.config.use_acked_bitrate_only_when_overusing {
            return true;
        }

        // TODO: consider passing this in as params
        for state in self.delay_detector_states.iter() {
            if *state == BandwidthUsage::Overuse {
                return true;
            }
        }

        false
    }

    fn is_bw_limited_due_to_loss(&self) -> bool {
        self.state != LossControllerState::DelayBased
    }

    fn initialize_temporal_weights(&mut self) {
        for i in 0..self.config.observation_window_size {
            let val = f64::powi(self.config.temporal_weight_factor, i as i32);
            self.temporal_weights[i] = val;
            let val = f64::powi(
                self.config.instant_upper_bound_temporal_weight_factor,
                i as i32,
            );
            self.instant_upper_bound_temporal_weights[i] = val;
        }
    }

    fn set_state(&mut self, state: LossControllerState) {
        if state != self.state {
            debug!(
                "Changing loss controller state: {:?} -> {:?}",
                self.state, state
            );
            dbg!(self.state, state);
        }
        self.state = state;
    }
}

#[derive(Debug)]
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

    pub fn from(records: &[TwccSendRecord]) -> Option<PacketResultsSummary> {
        let first = records.first()?;

        let mut summary =
            PacketResultsSummary::new(first.local_send_time(), first.local_send_time());
        for record in records {
            summary.num_packets += 1;
            summary.total_size += record.size() as u64;
            summary.first_send_time = min(summary.first_send_time, record.local_send_time());
            summary.last_send_time = max(summary.last_send_time, record.local_send_time());

            if record.remote_recv_time().is_none() {
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
        sending_rate: Bitrate::NEG_INFINITY,
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
            loss_limited_bandwidth: Bitrate::NEG_INFINITY,
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

pub struct LossBasedBweResult {
    bandwidth_estimate: Option<Bitrate>,
    state: LossControllerState,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            observation_window_size: 20, // minimum is 2
            observation_duration_lower_bound: Duration::from_millis(0),
            trendline_integration_enabled: false,
            trendline_observations_window_size: 40,
            temporal_weight_factor: 0.9,
            instant_upper_bound_temporal_weight_factor: 0.9,
            instant_upper_bound_loss_offset: 0.05,
            instant_upper_bound_bandwidth_balance: 75_000.0, // 75 kbps
            high_loss_rate_threshold: 1.0,
            slope_of_bwe_high_loss_function: 1000.0,
            bandtidth_cap_at_high_loss_rate: 50_000.0, // 500 kbps
            initial_inherent_loss_estimate: 0.01,
            inherent_loss_upper_bound_offset: 0.05,
            inherent_loss_upper_bound_bandwidth_balance: 75_000.0, // 75 kbps
            inherent_loss_upper_bound: 1.0e-3,
            newton_iterations: 1,
            newton_step_size: 0.75,
            use_acked_bitrate_only_when_overusing: false,
            not_increase_if_inherent_loss_less_than_average_loss: true,
            delayed_increase_window: Duration::from_millis(1000),
            bandwidth_rampup_upper_bound_factor: 1000000.0,
            probe_integration_enabled: false,
            candidate_factor: [1.02, 1.0, 0.95],
            append_acknowledged_rate_candidate: true,
            append_delay_based_estimate_candidate: true,
            bandwidth_backoff_lower_bound_factor: 1.0,
            rampup_acceleration_maxout_time: 60.0, // 60s
            rampup_acceleration_max_factor: 0.0,   // 60s
            higher_bandwidth_bias_factor: 0.0002,
            higher_log_bandwidth_bias_factor: 0.02,
            threshold_of_high_bandwidth_preference: 0.15,
            bandwidth_preference_smoothing_factor: 0.002,
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use fastrand::Rng;
    use systemstat::Duration;

    use crate::rtp_::SeqNo;

    use super::{
        BandwidthUsage, Bitrate, DataSize, LossBasedBweResult, LossController, LossControllerState,
        TwccSendRecord,
    };

    #[test]
    fn stable_loss() {
        // Test stable loss at 5% which should be ignored by the loss controller
        let mut lbc = LossController::new();
        lbc.set_min_bitrate(Bitrate::from(50_000)); // 50 kbps
        lbc.set_max_bitrate(Bitrate::from(1_000_000_000)); // 1 Gbps

        let acknowledged_bitrate = Bitrate::from(1_000_000); // 1 Mbps
        lbc.set_acknowledged_bitrate(acknowledged_bitrate);
        lbc.set_bandwidth_estimate(Bitrate::from(1_250_000)); // 1.25Mbps

        let mut pkt_builder = PacketBuilder::new(Instant::now())
            .with_loss(0.05)
            .num_packets(11);

        // 10 seconds of sending at ~1Mbps
        for _ in 0..200 {
            let result = pkt_builder.build_packets();
            lbc.update_bandwidth_estimate(
                &result,
                Bitrate::bps(1_500_000),
                BandwidthUsage::Underuse,
            );

            pkt_builder = pkt_builder.forward_time(Duration::from_millis(50));
        }

        let LossBasedBweResult {
            bandwidth_estimate,
            state,
        } = lbc.get_loss_based_result();

        assert_eq!(
            bandwidth_estimate,
            Some(Bitrate::bps(1_500_000)),
            "Stable loss should be ignored and not impact the estimate"
        );
        // TODO: Figure out if this is correct
        assert_eq!(state, LossControllerState::DelayBased);
    }

    #[test]
    fn stable_loss_with_loss_spike() {
        // Test stable loss at 5% which should be ignored by the loss controller, followed by a
        // loss spike which should cause the estimate to dip
        let mut lbc = LossController::new();
        lbc.set_min_bitrate(Bitrate::from(50_000)); // 50 kbps
        lbc.set_max_bitrate(Bitrate::from(1_000_000_000)); // 1 Gbps

        let acknowledged_bitrate = Bitrate::from(1_000_000); // 1 Mbps
        lbc.set_acknowledged_bitrate(acknowledged_bitrate);
        lbc.set_bandwidth_estimate(Bitrate::from(1_250_000)); // 1.25Mbps

        let mut pkt_builder = PacketBuilder::new(Instant::now())
            .with_loss(0.05)
            .num_packets(104);

        // 10 seconds of sending at ~1Mbps
        for _ in 0..10 {
            let result = pkt_builder.build_packets();
            lbc.update_bandwidth_estimate(
                &result,
                Bitrate::bps(1_500_000),
                BandwidthUsage::Underuse,
            );

            pkt_builder = pkt_builder.forward_time(Duration::from_millis(500));
        }

        pkt_builder = pkt_builder.with_loss(0.9);
        // Loss spike
        for _ in 0..2 {
            let result = pkt_builder.build_packets();
            lbc.update_bandwidth_estimate(
                &result,
                Bitrate::bps(1_500_000),
                BandwidthUsage::Underuse,
            );

            pkt_builder = pkt_builder.forward_time(Duration::from_millis(500));
        }

        let LossBasedBweResult {
            bandwidth_estimate,
            state,
        } = lbc.get_loss_based_result();

        let estimate = bandwidth_estimate.expect("Should have an estimate");
        assert!(
            estimate < Bitrate::bps(500_000),
            "A loss spike should result in a reduced estimate, estimate was {estimate}"
        );
        assert_eq!(state, LossControllerState::Decreasing);
    }

    #[test]
    fn loss_spike_recovery() {
        // Test stable loss at 5% which should be ignored by the loss controller, followed by a
        // loss spike which should cause the estimate to dip
        let mut lbc = LossController::new();
        lbc.set_min_bitrate(Bitrate::from(50_000)); // 50 kbps
        lbc.set_max_bitrate(Bitrate::from(1_000_000_000)); // 1 Gbps

        let acknowledged_bitrate = Bitrate::from(1_000_000); // 1 Mbps
        lbc.set_acknowledged_bitrate(acknowledged_bitrate);
        lbc.set_bandwidth_estimate(Bitrate::from(1_250_000)); // 1.25Mbps

        let mut pkt_builder = PacketBuilder::new(Instant::now())
            .with_loss(0.05)
            .num_packets(11);

        // 10 seconds of sending at ~1Mbps
        for _ in 0..200 {
            let result = pkt_builder.build_packets();
            lbc.update_bandwidth_estimate(
                &result,
                Bitrate::bps(1_500_000),
                BandwidthUsage::Underuse,
            );

            pkt_builder = pkt_builder.forward_time(Duration::from_millis(50));
        }

        pkt_builder = pkt_builder.with_loss(0.9);
        // Loss spike
        for _ in 0..40 {
            let result = pkt_builder.build_packets();
            lbc.update_bandwidth_estimate(
                &result,
                Bitrate::bps(1_500_000),
                BandwidthUsage::Underuse,
            );

            pkt_builder = pkt_builder.forward_time(Duration::from_millis(50));
        }
        let LossBasedBweResult {
            bandwidth_estimate,
            state,
        } = lbc.get_loss_based_result();

        // Set loss back to 5%
        pkt_builder = pkt_builder.with_loss(0.05);
        // Recovery
        for _ in 0..200 {
            let result = pkt_builder.build_packets();
            lbc.update_bandwidth_estimate(
                &result,
                Bitrate::bps(1_500_000),
                BandwidthUsage::Underuse,
            );

            pkt_builder = pkt_builder.forward_time(Duration::from_millis(50));
        }

        let LossBasedBweResult {
            bandwidth_estimate,
            state,
        } = lbc.get_loss_based_result();

        let estimate = bandwidth_estimate.expect("Should have an estimate");
        assert_eq!(
            estimate,
            Bitrate::bps(1_500_000),
            "A loss spike followed by a recovery should result in returning to the original estimate "
        );
        assert_eq!(state, LossControllerState::DelayBased);
    }

    #[test]
    fn stable_loss_gradual_overuse() {
        // Test stable loss at 5% which should be ignored by the loss controller, followed by a
        // a gradual increase in loss as we overuse the capacity
        let mut lbc = LossController::new();
        lbc.set_min_bitrate(Bitrate::from(50_000)); // 50 kbps
        lbc.set_max_bitrate(Bitrate::from(1_000_000_000)); // 1 Gbps

        let acknowledged_bitrate = Bitrate::from(1_000_000); // 1 Mbps
        lbc.set_acknowledged_bitrate(acknowledged_bitrate);
        lbc.set_bandwidth_estimate(Bitrate::from(1_250_000)); // 1.25Mbps

        let mut pkt_builder = PacketBuilder::new(Instant::now())
            .with_loss(0.05)
            .num_packets(11);

        // 10 seconds of sending at ~1Mbps
        for _ in 0..200 {
            let result = pkt_builder.build_packets();
            lbc.update_bandwidth_estimate(
                &result,
                Bitrate::bps(1_500_000),
                BandwidthUsage::Underuse,
            );

            pkt_builder = pkt_builder.forward_time(Duration::from_millis(50));
        }

        // Gradual increase
        for inc in 0..10 {
            pkt_builder = pkt_builder.with_loss(0.05 + (inc as f64 / 10.0));

            for _ in 0..4 {
                let result = pkt_builder.build_packets();
                lbc.update_bandwidth_estimate(
                    &result,
                    Bitrate::bps(1_500_000),
                    BandwidthUsage::Underuse,
                );

                pkt_builder = pkt_builder.forward_time(Duration::from_millis(50));
            }
        }

        let LossBasedBweResult {
            bandwidth_estimate,
            state,
        } = lbc.get_loss_based_result();

        let estimate = bandwidth_estimate.expect("Should have an estimate");
        assert!(
            estimate < Bitrate::bps(1_000_000),
            "A gradual overuse should result in a lowered estimate"
        );
        // TODO, why delay based
        // assert_eq!(state, LossControllerState::Decreasing);
    }

    struct PacketBuilder {
        now: Instant,
        rng: Rng,
        loss_rate: f64,
        send_distribution: LogNormalDistribution,
        recv_distribution: LogNormalDistribution,
        num_packets: u32,
        packet_size: DataSize,
        seq: SeqNo,
    }

    impl PacketBuilder {
        fn new(now: Instant) -> Self {
            Self {
                now,
                rng: Rng::with_seed(34791910),
                loss_rate: 0.0,
                send_distribution: LogNormalDistribution {
                    mean: 0.05,
                    std_dev: 1.0,
                },
                recv_distribution: LogNormalDistribution {
                    mean: 4.0,
                    std_dev: 10.0,
                },
                num_packets: 10,
                packet_size: DataSize::bytes(1200),
                seq: 0.into(),
            }
        }

        fn forward_time(mut self, by: Duration) -> Self {
            self.now += by;
            self
        }

        fn with_loss(mut self, loss_rate: f64) -> Self {
            self.loss_rate = loss_rate;
            self
        }

        fn num_packets(mut self, packets: u32) -> Self {
            self.num_packets = packets;
            self
        }

        fn build_packets(&mut self) -> Vec<TwccSendRecord> {
            let mut last_send_time = self.now;
            let mut last_recv_time = self.now;
            let mut result: Vec<TwccSendRecord> = Vec::with_capacity(self.num_packets as usize);

            for i in 0..self.num_packets {
                let lost = self.rng.f64() <= self.loss_rate;
                let first_send_time = last_send_time
                    + Duration::from_secs_f64(
                        self.send_distribution.sample(&mut self.rng) / 1000.0,
                    );
                let recv_time = last_recv_time
                    + Duration::from_secs_f64(
                        self.recv_distribution.sample(&mut self.rng) / 1000.0,
                    );

                result.push(TwccSendRecord::new_reported(
                    self.seq,
                    first_send_time,
                    self.packet_size.as_bytes_usize() as u16,
                    first_send_time + Duration::from_nanos(50),
                    (!lost).then_some(recv_time),
                ));

                last_send_time = first_send_time;
                if !lost {
                    last_recv_time = recv_time;
                }
            }

            result
        }
    }

    struct LogNormalDistribution {
        mean: f64,
        std_dev: f64,
    }

    impl LogNormalDistribution {
        fn sample(&self, rng: &mut Rng) -> f64 {
            let normal = normal_distribution(rng);
            let location =
                (self.mean.powi(2) / (self.mean.powi(2) + self.std_dev.powi(2)).sqrt()).ln();
            let scale = (1.0 + (self.std_dev / self.mean).powi(2)).ln().sqrt();

            (location + scale * normal).exp()
        }
    }

    fn normal_distribution(rng: &mut Rng) -> f64 {
        let u1 = rng.f64();
        let u2 = rng.f64();

        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
}
