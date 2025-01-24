use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::rtp_::Bitrate;
use crate::util::already_happened;

use super::arrival_group::ArrivalGroupAccumulator;
use super::rate_control::RateControl;
use super::trendline_estimator::TrendlineEstimator;
use super::{AckedPacket, BandwidthUsage};

const MAX_RTT_HISTORY_WINDOW: usize = 32;
const UPDATE_INTERVAL: Duration = Duration::from_millis(25);
/// The maximum time we keep updating our estimate without receiving a TWCC report.
const MAX_TWCC_GAP: Duration = Duration::from_millis(500);

/// Delay controller for googcc inspired BWE.
///
/// This controller attempts to estimate the available send bandwidth by looking at the variations
/// in packet arrival times for groups of packets sent together. Broadly, if the delay variation is
/// increasing this indicates overuse.
pub struct DelayController {
    arrival_group_accumulator: ArrivalGroupAccumulator,
    trendline_estimator: TrendlineEstimator,
    rate_control: RateControl,
    /// Last estimate produced, unlike [`next_estimate`] this will always have a value after the
    /// first estimate.
    last_estimate: Option<Bitrate>,
    /// History of the max RTT derived for each TWCC report.
    max_rtt_history: VecDeque<Duration>,
    /// Calculated mean of max_rtt_history.
    mean_max_rtt: Option<Duration>,

    /// The next time we should poll.
    next_timeout: Instant,
    /// The last time we ingested a TWCC report.
    last_twcc_report: Instant,
}

impl DelayController {
    pub fn new(initial_bitrate: Bitrate) -> Self {
        Self {
            arrival_group_accumulator: ArrivalGroupAccumulator::default(),
            trendline_estimator: TrendlineEstimator::new(20),
            rate_control: RateControl::new(initial_bitrate, Bitrate::kbps(40), Bitrate::gbps(10)),
            last_estimate: None,
            max_rtt_history: VecDeque::default(),
            mean_max_rtt: None,
            next_timeout: already_happened(),
            last_twcc_report: already_happened(),
        }
    }

    /// Record a packet from a TWCC report.
    pub(crate) fn update(
        &mut self,
        acked: &[AckedPacket],
        acked_bitrate: Option<Bitrate>,
        now: Instant,
    ) -> Option<Bitrate> {
        let mut max_rtt = None;

        for acked_packet in acked {
            max_rtt = max_rtt.max(Some(acked_packet.rtt()));
            if let Some(delay_variation) = self
                .arrival_group_accumulator
                .accumulate_packet(acked_packet)
            {
                crate::packet::bwe::macros::log_delay_variation!(delay_variation.arrival_delta);

                // Got a new delay variation, add it to the trendline
                self.trendline_estimator
                    .add_delay_observation(delay_variation, now);
            }
        }

        if let Some(rtt) = max_rtt {
            self.add_max_rtt(rtt);
        }

        let new_hypothesis = self.trendline_estimator.hypothesis();

        self.update_estimate(new_hypothesis, acked_bitrate, self.mean_max_rtt, now);
        self.last_twcc_report = now;

        self.last_estimate
    }

    pub(crate) fn poll_timeout(&self) -> Instant {
        self.next_timeout
    }

    pub(crate) fn handle_timeout(&mut self, acked_bitrate: Option<Bitrate>, now: Instant) {
        if !self.trendline_hypothesis_valid(now) {
            // We haven't received a TWCC report in a while. The trendline hypothesis can
            // no longer be considered valid. We need another TWCC report before we can update
            // estimates.
            let next_timeout_in = self
                .mean_max_rtt
                .unwrap_or(MAX_TWCC_GAP)
                .min(UPDATE_INTERVAL);

            // Set this even if we didn't update, otherwise we get stuck in a poll -> handle loop
            // that starves the run loop.
            self.next_timeout = now + next_timeout_in;
            return;
        }

        self.update_estimate(
            self.trendline_estimator.hypothesis(),
            acked_bitrate,
            self.mean_max_rtt,
            now,
        );
    }

    /// Get the latest estimate.
    pub(crate) fn last_estimate(&self) -> Option<Bitrate> {
        self.last_estimate
    }

    fn add_max_rtt(&mut self, max_rtt: Duration) {
        while self.max_rtt_history.len() > MAX_RTT_HISTORY_WINDOW {
            self.max_rtt_history.pop_front();
        }
        self.max_rtt_history.push_back(max_rtt);

        let sum = self
            .max_rtt_history
            .iter()
            .fold(Duration::ZERO, |acc, rtt| acc + *rtt);

        self.mean_max_rtt = Some(sum / self.max_rtt_history.len() as u32);
    }

    fn update_estimate(
        &mut self,
        hypothesis: BandwidthUsage,
        observed_bitrate: Option<Bitrate>,
        mean_max_rtt: Option<Duration>,
        now: Instant,
    ) {
        if let Some(observed_bitrate) = observed_bitrate {
            self.rate_control
                .update(hypothesis.into(), observed_bitrate, mean_max_rtt, now);
            let estimated_rate = self.rate_control.estimated_bitrate();

            crate::packet::bwe::macros::log_bitrate_estimate!(estimated_rate.as_f64());
            self.last_estimate = Some(estimated_rate);
        }

        // Set this even if we didn't update, otherwise we get stuck in a poll -> handle loop
        // that starves the run loop.
        self.next_timeout = now + UPDATE_INTERVAL;
    }

    /// Whether the current trendline hypothesis is valid i.e. not too old.
    fn trendline_hypothesis_valid(&self, now: Instant) -> bool {
        now.duration_since(self.last_twcc_report)
            <= self
                .mean_max_rtt
                .map(|rtt| rtt * 2)
                .unwrap_or(MAX_TWCC_GAP)
                .min(UPDATE_INTERVAL * 2)
    }
}
