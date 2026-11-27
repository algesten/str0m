use std::time::{Duration, Instant};

use super::super::macros::{log_bitrate_estimate, log_delay_variation};
use super::super::{AckedPacket, BandwidthUsage, MIN_BITRATE};
use super::arrival_group::ArrivalGroupAccumulator;
use super::rate_control::RateControl;
use super::trendline::TrendlineEstimator;
use crate::rtp_::Bitrate;

/// Delay controller for googcc inspired BWE.
///
/// This controller attempts to estimate the available send bandwidth by looking at the variations
/// in packet arrival times for groups of packets sent together. Broadly, if the delay variation is
/// increasing this indicates overuse.
pub struct DelayController {
    clock_origin: Option<Instant>,
    arrival_group_accumulator: ArrivalGroupAccumulator,
    trendline_estimator: TrendlineEstimator,
    rate_control: RateControl,
    /// Last estimate produced, unlike [`next_estimate`] this will always have a value after the
    /// first estimate.
    last_estimate: Option<Bitrate>,
    last_observed_bitrate: Bitrate,
    rtt: Duration,
}

impl DelayController {
    pub fn new(initial_bitrate: Bitrate) -> Self {
        Self {
            clock_origin: None,
            arrival_group_accumulator: ArrivalGroupAccumulator::default(),
            trendline_estimator: TrendlineEstimator::new(20),
            rate_control: RateControl::new(initial_bitrate, MIN_BITRATE, Bitrate::gbps(10)),
            last_estimate: Some(initial_bitrate),
            last_observed_bitrate: initial_bitrate,
            rtt: Duration::from_millis(200),
        }
    }

    pub fn start_clock(&mut self, now: Instant) {
        self.clock_origin.get_or_insert(now);
    }

    /// Record a packet from a TWCC report.
    pub fn update(
        &mut self,
        acked: &[AckedPacket],
        acked_bitrate: Option<Bitrate>,
        probe_bitrate: Option<Bitrate>,
        now: Instant,
    ) -> Option<Bitrate> {
        for acked_packet in acked {
            let variation = self
                .arrival_group_accumulator
                .accumulate_packet(acked_packet);
            let Some(mut delay_variation) = variation else {
                continue;
            };
            log_delay_variation!(delay_variation.arrival_delta);

            // Got a new delay variation, add it to the trendline.
            //
            // IMPORTANT: Match WebRTC's TrendlineEstimator time base.
            // WebRTC calls Detect/UpdateThreshold with `arrival_time_ms` (remote receive time),
            // not the local "time we processed this feedback". Using the remote receive time
            // avoids threshold adaptation artifacts when many deltas are processed in one
            // feedback batch (e.g. TWCC reports).
            //
            // Note: We use remote timestamps for relative timing only (computing time deltas
            // between packets). Clock skew doesn't matter since we're measuring trends in
            // delay variations, not absolute times.
            delay_variation.last_remote_recv_time =
                self.trendline_timestamp(delay_variation.last_remote_recv_time);
            self.trendline_estimator
                .add_delay_observation(delay_variation, delay_variation.last_remote_recv_time);
        }

        let new_hypothesis = self.trendline_estimator.hypothesis();

        if !acked.is_empty() {
            self.update_estimate(new_hypothesis, acked_bitrate, probe_bitrate, now);
        }

        self.last_estimate
    }

    // GoogCC passes receive_time.ms() to TrendlineEstimator. Round each
    // timestamp on a shared clock before taking differences, while keeping
    // the inter-group send and receive deltas at transport precision.
    fn trendline_timestamp(&mut self, at: Instant) -> Instant {
        let origin = *self.clock_origin.get_or_insert(at);
        let elapsed = at.max(origin).duration_since(at.min(origin));
        let milliseconds =
            elapsed.as_millis() as u64 + u64::from(elapsed.subsec_nanos() % 1_000_000 >= 500_000);
        let offset = Duration::from_millis(milliseconds);
        if at >= origin {
            origin + offset
        } else {
            origin - offset
        }
    }

    /// Get the latest estimate.
    pub fn last_estimate(&self) -> Option<Bitrate> {
        self.last_estimate
    }

    /// Whether the delay-based detector currently signals overuse.
    ///
    /// This is useful for gating behaviors (like probing) that would otherwise
    /// re-excite the system while we're already congested.
    pub fn is_overusing(&self) -> bool {
        self.trendline_estimator.hypothesis() == BandwidthUsage::Overuse
    }

    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
    }

    fn update_estimate(
        &mut self,
        hypothesis: BandwidthUsage,
        observed_bitrate: Option<Bitrate>,
        probe_bitrate: Option<Bitrate>,
        now: Instant,
    ) {
        if let Some(rate) = observed_bitrate {
            self.last_observed_bitrate = rate;
        }

        let probe_bitrate = probe_bitrate.filter(|_| hypothesis != BandwidthUsage::Overuse);
        if let Some(mut probe_rate) = probe_bitrate {
            if let (Some(previous), Some(throughput)) = (self.last_estimate, observed_bitrate) {
                probe_rate = probe_rate.max(previous.min(throughput * 0.85));
            }
            // Apply probe result directly, bypassing delay-based updates
            self.rate_control.set_probe_result(probe_rate, now);
            let estimated_rate = self.rate_control.estimated_bitrate();
            log_bitrate_estimate!(estimated_rate.as_f64());
            self.last_estimate = Some(estimated_rate);
        } else if observed_bitrate.is_some() || hypothesis != BandwidthUsage::Overuse {
            // No probe result, apply normal delay-based rate control
            self.rate_control.update(
                hypothesis.into(),
                self.last_observed_bitrate,
                Some(self.rtt),
                now,
            );
            let estimated_rate = self.rate_control.estimated_bitrate();

            log_bitrate_estimate!(estimated_rate.as_f64());
            self.last_estimate = Some(estimated_rate);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn trendline_rounds_arrivals_before_measuring_elapsed_time() {
        let start = Instant::now();
        let mut controller = DelayController::new(Bitrate::kbps(300));
        controller.start_clock(start);
        let at = |us| start + Duration::from_micros(us);
        assert_eq!(controller.trendline_timestamp(at(1499)), at(1000));
        assert_eq!(controller.trendline_timestamp(at(1500)), at(2000));
        assert_eq!(
            controller.trendline_timestamp(start - Duration::from_micros(750)),
            start - Duration::from_millis(1)
        );
    }

    #[test]
    fn first_normal_feedback_can_raise_target_before_throughput_is_available() {
        let mut controller = DelayController::new(Bitrate::kbps(300));
        controller.update_estimate(BandwidthUsage::Normal, None, None, Instant::now());
        assert_eq!(controller.last_estimate(), Some(Bitrate::kbps(301)));
    }
}
