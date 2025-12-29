use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::ProbeClusterConfig;
use crate::rtp_::{Bitrate, TwccClusterId};
use crate::util::{already_happened, not_happening};

// Port notes:
// This module ports WebRTC's `ProbeController` behavior from:
// `webrtc/modules/congestion_controller/goog_cc/probe_controller.cc`
//
// Key integration difference (requested): WebRTC returns vectors of probe clusters, while str0m
// returns a single `ProbeClusterConfig` per tick. We therefore queue configs internally and make
// `poll_timeout()` return `already_happened()` until the queue is drained.

/// WebRTC: `kMaxWaitingTimeForProbingResult`.
const MAX_WAITING_TIME_FOR_PROBING_RESULT: Duration = Duration::from_secs(1);

/// WebRTC: `kBitrateDropThreshold`, `kBitrateDropTimeout`, `kProbeFractionAfterDrop`,
/// `kProbeUncertainty`, `kAlrEndedTimeout`, `kMinTimeBetweenAlrProbes`.
const BITRATE_DROP_THRESHOLD: f64 = 0.66;
const BITRATE_DROP_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_FRACTION_AFTER_DROP: f64 = 0.85;
const PROBE_UNCERTAINTY: f64 = 0.05;
const ALR_ENDED_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_TIME_BETWEEN_ALR_PROBES: Duration = Duration::from_secs(5);

/// WebRTC's `BandwidthLimitedCause` (subset used by probing gating).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthLimitedCause {
    LossLimitedBweIncreasing,
    LossLimitedBwe,
    DelayBasedLimited,
    DelayBasedLimitedDelayIncreased,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Init,
    WaitingForProbingResult,
    ProbingComplete,
}

/// Configuration using WebRTC default constants (no field-trial plumbing).
#[derive(Debug, Clone, Copy)]
struct Config {
    // Initial/exponential probing
    first_exponential_probe_scale: f64,   // p1 = 3.0
    second_exponential_probe_scale: f64,  // p2 = 6.0
    further_exponential_probe_scale: f64, // step_size = 2.0
    further_probe_threshold: f64,         // 0.7

    // Allocation probing
    first_allocation_probe_scale: f64,            // 1.0
    second_allocation_probe_scale: f64,           // 2.0
    allocation_probe_limit_by_current_scale: f64, // 2.0

    // Probe cluster config defaults
    min_probe_packets_sent: usize, // 5
    min_probe_duration: Duration,  // 15ms
    min_probe_delta: Duration,     // 2ms

    // Gating / limits
    loss_limited_probe_scale: f64, // 1.5
}

impl Default for Config {
    fn default() -> Self {
        Self {
            first_exponential_probe_scale: 3.0,
            second_exponential_probe_scale: 6.0,
            further_exponential_probe_scale: 2.0,
            further_probe_threshold: 0.7,

            first_allocation_probe_scale: 1.0,
            second_allocation_probe_scale: 2.0,
            allocation_probe_limit_by_current_scale: 2.0,

            min_probe_packets_sent: 5,
            min_probe_duration: Duration::from_millis(15),
            min_probe_delta: Duration::from_millis(2),

            loss_limited_probe_scale: 1.5,
        }
    }
}

pub struct ProbeControl {
    config: Config,

    state: State,

    bandwidth_limited_cause: BandwidthLimitedCause,
    estimated_bitrate: Bitrate,

    start_bitrate: Bitrate,
    max_bitrate: Bitrate,

    // ALR state.
    alr_start_time: Option<Instant>,
    alr_end_time: Option<Instant>,

    // Probing state.
    min_bitrate_to_probe_further: Bitrate,
    time_last_probing_initiated: Instant,

    // Cluster IDs + pending configs for "one per tick" integration.
    next_cluster_id: TwccClusterId,
    pending: VecDeque<ProbeClusterConfig>,

    // Large drop recovery tracking.
    time_of_last_large_drop: Instant,
    bitrate_before_last_large_drop: Bitrate,
    last_bwe_drop_probing_time: Instant,

    // Change flags for handle_timeout evaluation.
    max_bitrate_changed: bool,

    // Next time we should call `handle_timeout` for `process()`-driven decisions.
    next_timeout: Instant,
}

impl ProbeControl {
    pub fn new() -> Self {
        let now = already_happened();
        Self {
            config: Config::default(),
            state: State::Init,
            bandwidth_limited_cause: BandwidthLimitedCause::DelayBasedLimited,
            estimated_bitrate: Bitrate::ZERO,
            start_bitrate: Bitrate::ZERO,
            max_bitrate: Bitrate::ZERO,
            alr_start_time: None,
            alr_end_time: None,
            min_bitrate_to_probe_further: Bitrate::INFINITY,
            time_last_probing_initiated: now,
            next_cluster_id: TwccClusterId::default(),
            pending: VecDeque::new(),
            time_of_last_large_drop: now,
            bitrate_before_last_large_drop: Bitrate::ZERO,
            last_bwe_drop_probing_time: now,
            max_bitrate_changed: false,
            next_timeout: not_happening(),
        }
    }

    pub fn poll_timeout(&self) -> Instant {
        if !self.pending.is_empty() {
            return already_happened();
        }
        self.next_timeout
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        // Equivalent of WebRTC `ProbeController::Process(at_time)`.
        self.process(now);
        self.next_timeout = self.compute_next_timeout(now);
    }

    /// Update whether we are in ALR (Application Limited Region).
    ///
    /// This mirrors WebRTC `SetAlrStartTime` / `SetAlrEndedTime` handling.
    pub fn set_alr_start_time(&mut self, alr_start_time: Option<Instant>, now: Instant) {
        // Track ALR end time for "ALR ended recently" logic.
        if self.alr_start_time.is_some() && alr_start_time.is_none() {
            self.alr_end_time = Some(now);
        }
        self.alr_start_time = alr_start_time;
    }

    pub fn set_estimated_bitrate(
        &mut self,
        bitrate: Bitrate,
        cause: BandwidthLimitedCause,
        now: Instant,
    ) {
        self.bandwidth_limited_cause = cause;

        // Track large drops (WebRTC: SetEstimatedBitrate).
        if bitrate < self.estimated_bitrate * BITRATE_DROP_THRESHOLD {
            self.time_of_last_large_drop = now;
            self.bitrate_before_last_large_drop = self.estimated_bitrate;
            self.next_timeout = already_happened();
        }

        self.estimated_bitrate = bitrate;

        // If waiting for probing result, trigger evaluation for further probing.
        if self.state == State::WaitingForProbingResult
            && bitrate > self.min_bitrate_to_probe_further
        {
            self.next_timeout = already_happened();
        }
    }

    /// Called when the BWE becomes "active" (first media sent / probing allowed).
    ///
    /// This is the str0m replacement for WebRTC's `OnNetworkAvailability()` trigger.
    pub fn on_bwe_active(&mut self, start_bitrate: Bitrate) {
        if start_bitrate > Bitrate::ZERO {
            self.start_bitrate = start_bitrate;
            if self.estimated_bitrate == Bitrate::ZERO {
                self.estimated_bitrate = start_bitrate;
            }
        }

        if self.state == State::Init && self.start_bitrate > Bitrate::ZERO {
            self.next_timeout = already_happened();
        }
    }

    /// Update max bitrate (application's desired sending rate).
    ///
    /// In str0m, this represents both WebRTC's `max_bitrate` (hard cap) and
    /// `max_total_allocated_bitrate` (sum of stream allocations). Since str0m
    /// doesn't track per-stream bitrates, these are unified into a single value.
    ///
    /// This may trigger allocation probing when in ALR and the max increases.
    pub fn set_max_bitrate(&mut self, max_bitrate: Bitrate) {
        if max_bitrate != self.max_bitrate {
            self.max_bitrate = max_bitrate;
            self.max_bitrate_changed = true;
            self.next_timeout = already_happened();
        }
    }

    /// Return the next queued probe config, if any (one per tick).
    pub fn maybe_create_probe(&mut self) -> Option<ProbeClusterConfig> {
        self.pending.pop_front()
    }

    fn process(&mut self, now: Instant) {
        match self.state {
            State::Init => self.process_init(now),
            State::WaitingForProbingResult => self.process_waiting_for_probing_result(now),
            State::ProbingComplete => self.process_probing_complete(now),
        }
    }

    fn process_init(&mut self, now: Instant) {
        // Initial exponential probing (on BWE becoming active).
        if self.start_bitrate > Bitrate::ZERO {
            self.initiate_exponential_probing(now);
        }
    }

    fn process_waiting_for_probing_result(&mut self, now: Instant) {
        let since_last_probing_initiated =
            now.saturating_duration_since(self.time_last_probing_initiated);

        // Timeout waiting-for-probing-result state.
        if since_last_probing_initiated > MAX_WAITING_TIME_FOR_PROBING_RESULT {
            self.update_state(State::ProbingComplete);
            // Fall through to process_probing_complete logic.
            self.process_probing_complete(now);
            return;
        }

        // Further exponential probing (when estimate increased enough).
        if self.estimated_bitrate > self.min_bitrate_to_probe_further {
            let target = self.estimated_bitrate * self.config.further_exponential_probe_scale;
            self.initiate_probing(now, vec![target], true, self.alr_start_time.is_some());
        }
    }

    fn process_probing_complete(&mut self, now: Instant) {
        // 1. Allocation probing (max_bitrate increased while in ALR).
        if self.max_bitrate_changed {
            self.max_bitrate_changed = false;

            let in_alr = self.alr_start_time.is_some();
            if in_alr && self.estimated_bitrate < self.max_bitrate {
                self.initiate_allocation_probing(now);
                return; // Early return
            }
        }

        // 2. Large-drop recovery probing.
        self.maybe_request_probe_after_large_drop(now);
    }

    fn initiate_allocation_probing(&mut self, now: Instant) {
        let current_bwe_limit =
            self.estimated_bitrate * self.config.allocation_probe_limit_by_current_scale;

        let mut first_probe_rate = self.max_bitrate * self.config.first_allocation_probe_scale;
        let mut limited_by_current_bwe = current_bwe_limit < first_probe_rate;
        if limited_by_current_bwe {
            first_probe_rate = current_bwe_limit;
        }

        let mut probes = vec![first_probe_rate];
        if !limited_by_current_bwe {
            let mut second_probe_rate =
                self.max_bitrate * self.config.second_allocation_probe_scale;
            limited_by_current_bwe = current_bwe_limit < second_probe_rate;
            if limited_by_current_bwe {
                second_probe_rate = current_bwe_limit;
            }
            if second_probe_rate > first_probe_rate {
                probes.push(second_probe_rate);
            }
        }

        let allow_further_probing = limited_by_current_bwe;
        self.initiate_probing(now, probes, allow_further_probing, true);
    }

    fn compute_next_timeout(&self, _now: Instant) -> Instant {
        if !self.pending.is_empty() {
            return already_happened();
        }

        // Waiting-for-probing-result timeout.
        if self.state == State::WaitingForProbingResult {
            return self.time_last_probing_initiated + MAX_WAITING_TIME_FOR_PROBING_RESULT;
        }

        not_happening()
    }

    fn update_state(&mut self, new_state: State) {
        self.state = new_state;
        if self.state == State::ProbingComplete {
            self.min_bitrate_to_probe_further = Bitrate::INFINITY;
        }
    }

    fn initiate_exponential_probing(&mut self, now: Instant) {
        let mut probes = vec![self.start_bitrate * self.config.first_exponential_probe_scale];
        // WebRTC's second exponential probe is optional; in defaults it's present and > 0.
        probes.push(self.start_bitrate * self.config.second_exponential_probe_scale);

        self.initiate_probing(now, probes, true, self.alr_start_time.is_some());
    }

    fn create_probe_cluster_config(
        &mut self,
        bitrate: Bitrate,
        is_alr_probe: bool,
    ) -> ProbeClusterConfig {
        ProbeClusterConfig::new(self.next_cluster_id.inc(), bitrate, is_alr_probe)
            .with_min_packet_count(self.config.min_probe_packets_sent)
            .with_duration(self.config.min_probe_duration)
            .with_min_probe_delta(self.config.min_probe_delta)
    }

    fn initiate_probing(
        &mut self,
        now: Instant,
        bitrates_to_probe: Vec<Bitrate>,
        mut probe_further: bool,
        is_alr_probe: bool,
    ) {
        // Use max_bitrate if set, otherwise allow unlimited probing (initial probing case).
        let mut max_probe_bitrate = if self.max_bitrate > Bitrate::ZERO {
            self.max_bitrate * 2.0
        } else {
            Bitrate::INFINITY
        };

        match self.bandwidth_limited_cause {
            BandwidthLimitedCause::DelayBasedLimitedDelayIncreased
            | BandwidthLimitedCause::LossLimitedBwe => {
                return;
            }
            BandwidthLimitedCause::LossLimitedBweIncreasing => {
                max_probe_bitrate = max_probe_bitrate
                    .min(self.estimated_bitrate * self.config.loss_limited_probe_scale);
            }
            BandwidthLimitedCause::DelayBasedLimited => {}
        }

        // Apply max cap and enqueue configs.
        for mut bitrate in bitrates_to_probe {
            if bitrate >= max_probe_bitrate {
                bitrate = max_probe_bitrate;
                probe_further = false;
            }
            let cfg = self.create_probe_cluster_config(bitrate, is_alr_probe);
            self.pending.push_back(cfg);
        }

        self.time_last_probing_initiated = now;
        if probe_further {
            self.update_state(State::WaitingForProbingResult);
            if let Some(last) = self.pending.back() {
                self.min_bitrate_to_probe_further =
                    last.target_bitrate() * self.config.further_probe_threshold;
            } else {
                self.min_bitrate_to_probe_further = Bitrate::INFINITY;
            }
        } else {
            self.update_state(State::ProbingComplete);
        }

        // Next timeout is re-computed in `handle_timeout`.
    }

    fn maybe_request_probe_after_large_drop(&mut self, now: Instant) {
        // WebRTC probes after a large drop only if we're in ALR, just left ALR, or if rapid recovery
        // experiment is enabled. str0m does not implement that experiment toggle, so we use ALR/left-ALR.
        let in_alr = self.alr_start_time.is_some();
        let alr_ended_recently = self
            .alr_end_time
            .map(|t| now.saturating_duration_since(t) < ALR_ENDED_TIMEOUT)
            .unwrap_or(false);

        if !(in_alr || alr_ended_recently) {
            return;
        }

        if self.state != State::ProbingComplete {
            return;
        }

        let suggested_probe = self.bitrate_before_last_large_drop * PROBE_FRACTION_AFTER_DROP;
        let min_expected_probe_result = suggested_probe * (1.0 - PROBE_UNCERTAINTY);
        let time_since_drop = now.saturating_duration_since(self.time_of_last_large_drop);
        let time_since_probe = now.saturating_duration_since(self.last_bwe_drop_probing_time);

        if min_expected_probe_result > self.estimated_bitrate
            && time_since_drop < BITRATE_DROP_TIMEOUT
            && time_since_probe > MIN_TIME_BETWEEN_ALR_PROBES
        {
            self.last_bwe_drop_probing_time = now;
            self.initiate_probing(now, vec![suggested_probe], false, in_alr);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn initial_exponential_probes_are_queued_and_emitted_one_per_tick() {
        let mut pc = ProbeControl::new();
        let now = Instant::now();

        pc.set_max_bitrate(Bitrate::mbps(50));
        pc.set_estimated_bitrate(
            Bitrate::kbps(300),
            BandwidthLimitedCause::DelayBasedLimited,
            now,
        );
        pc.on_bwe_active(Bitrate::kbps(300));
        pc.handle_timeout(now);

        // WebRTC initial exponential probing emits two clusters (3x and 6x).
        assert_eq!(pc.poll_timeout(), already_happened());

        let p1 = pc.maybe_create_probe().unwrap();
        // One left -> still immediate.
        assert_eq!(pc.poll_timeout(), already_happened());
        let p2 = pc.maybe_create_probe().unwrap();
        assert_eq!(p1.target_bitrate(), Bitrate::kbps(900));
        assert_eq!(p2.target_bitrate(), Bitrate::kbps(1800));
        assert_eq!(p1.min_packet_count(), 5);
        assert_eq!(p1.min_probe_delta(), Duration::from_millis(2));
        assert!(!p1.is_alr_probe());

        // Queue drained.
        assert!(pc.maybe_create_probe().is_none());
    }

    #[test]
    fn further_probe_is_triggered_when_probe_result_is_high_enough() {
        let mut pc = ProbeControl::new();
        let now = Instant::now();

        pc.set_max_bitrate(Bitrate::mbps(50));
        pc.set_estimated_bitrate(
            Bitrate::mbps(1),
            BandwidthLimitedCause::DelayBasedLimited,
            now,
        );
        pc.on_bwe_active(Bitrate::mbps(1));
        pc.handle_timeout(now);

        // Drain initial two probes.
        let _ = pc.maybe_create_probe().unwrap();
        let _ = pc.maybe_create_probe().unwrap();

        // WebRTC rule: if measured bitrate > min_bitrate_to_probe_further, probe at 2x measured.
        // min_bitrate_to_probe_further is 0.7 * last_probe_rate (6x start) = 4.2 Mbps.
        pc.set_estimated_bitrate(
            Bitrate::mbps(5),
            BandwidthLimitedCause::DelayBasedLimited,
            now + Duration::from_millis(10),
        );
        pc.handle_timeout(now + Duration::from_millis(10));

        let p = pc.maybe_create_probe().unwrap();
        assert_eq!(p.target_bitrate(), Bitrate::mbps(10));
    }

    #[test]
    fn allocation_probe_is_triggered_in_alr_when_allocation_increases() {
        let mut pc = ProbeControl::new();
        let now = Instant::now();

        pc.set_max_bitrate(Bitrate::mbps(50));
        pc.set_estimated_bitrate(
            Bitrate::mbps(1),
            BandwidthLimitedCause::DelayBasedLimited,
            now,
        );
        pc.on_bwe_active(Bitrate::mbps(1));
        pc.handle_timeout(now);

        // Drain initial probes.
        let _ = pc.maybe_create_probe().unwrap();
        let _ = pc.maybe_create_probe().unwrap();

        // Time out waiting for probing result -> probing complete.
        pc.handle_timeout(now + Duration::from_secs(2));

        // Enter ALR and increase allocation.
        pc.set_alr_start_time(Some(now), now + Duration::from_secs(2));
        pc.set_max_bitrate(Bitrate::mbps(4));
        pc.handle_timeout(now + Duration::from_secs(2));

        // With estimate=1 Mbps, current-bwe-limit=2 Mbps, so allocation probe is capped to 2 Mbps.
        let p = pc.maybe_create_probe().unwrap();
        assert_eq!(p.target_bitrate(), Bitrate::mbps(2));
        assert!(p.is_alr_probe());
    }
}
