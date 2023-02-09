mod arrival_group;
pub(crate) mod macros;
mod rate_control;
mod trendline_estimator;

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp::{Bitrate, SeqNo, TwccSendRecord};

use arrival_group::{ArrivalGroupAccumulator, InterGroupDelayVariation};
use rate_control::RateControl;
use trendline_estimator::TrendlineEstimator;

const MAX_RTT_HISTORY_WINDOW: usize = 32;

#[derive(Debug, Copy, Clone)]
pub struct AckedPacket {
    seq_no: SeqNo,
    local_send_time: Instant,
    remote_recv_time: Instant,
}

pub struct SendSideBandwithEstimator {
    arrival_group_accumulator: ArrivalGroupAccumulator,
    trendline_estimator: TrendlineEstimator,
    rate_control: RateControl,
    /// Last unpolled bitrate estimate.
    next_estimate: Option<Bitrate>,
    /// Last estimate produced
    last_estimate: Option<Bitrate>,
    max_rtt_history: VecDeque<Duration>,
}

impl SendSideBandwithEstimator {
    pub fn new(initial_bitrate: Bitrate) -> Self {
        Self {
            arrival_group_accumulator: ArrivalGroupAccumulator::default(),
            trendline_estimator: TrendlineEstimator::new(20),
            rate_control: RateControl::new(initial_bitrate, Bitrate::kbps(40), Bitrate::gbps(10)),
            next_estimate: None,
            last_estimate: None,
            max_rtt_history: VecDeque::default(),
        }
    }

    /// Record a packet from a TWCC report.
    pub(crate) fn update<'t>(
        &mut self,
        records: impl Iterator<Item = &'t TwccSendRecord>,
        observed_bitrate: Bitrate,
        now: Instant,
    ) {
        let mut max_rtt = None;
        for record in records {
            let Ok(acked_packet) = record.try_into() else {
                continue;
            };
            max_rtt = max_rtt.max(record.rtt());

            if let Some(delay_variation) = self
                .arrival_group_accumulator
                .accumulate_packet(acked_packet)
            {
                crate::packet::bwe::macros::log_delay_variation!(delay_variation.delay);

                // Got a new delay variation, add it to the trendline
                self.trendline_estimator
                    .add_delay_observation(delay_variation, now);
            }
        }
        if let Some(rtt) = max_rtt {
            self.add_max_rtt(rtt);
        }

        let new_hypothesis = self.trendline_estimator.hypothesis();

        if let Some(rtt) = self.mean_max_rtt() {
            self.rate_control.update_rtt(rtt);
        }
        self.rate_control
            .update(new_hypothesis.into(), observed_bitrate, now);
        let estimated_rate = self.rate_control.estimated_bitrate();

        self.update_estimate(estimated_rate);
    }

    /// Poll for an estimate.
    pub(crate) fn poll_estimate(&mut self) -> Option<u64> {
        self.next_estimate.take().map(|b| b.as_u64())
    }

    /// Get the latest estimate.
    pub(crate) fn last_estimate(&self) -> Option<Bitrate> {
        self.last_estimate
    }

    pub(crate) fn set_is_probing(&mut self, is_probing: bool, now: Instant) {
        self.rate_control.set_is_probing(is_probing, now);
    }

    fn add_max_rtt(&mut self, max_rtt: Duration) {
        while self.max_rtt_history.len() > MAX_RTT_HISTORY_WINDOW {
            self.max_rtt_history.pop_front();
        }
        self.max_rtt_history.push_back(max_rtt);
    }

    fn mean_max_rtt(&self) -> Option<Duration> {
        if self.max_rtt_history.is_empty() {
            return None;
        }

        let sum = self
            .max_rtt_history
            .iter()
            .fold(Duration::ZERO, |acc, rtt| acc + *rtt);

        Some(sum / self.max_rtt_history.len() as u32)
    }

    fn update_estimate(&mut self, estimated_rate: Bitrate) {
        crate::packet::bwe::macros::log_bitrate_estimate!(estimated_rate.as_f64());
        self.next_estimate = Some(estimated_rate);
        self.last_estimate = Some(estimated_rate);
    }
}

impl TryFrom<&TwccSendRecord> for AckedPacket {
    type Error = ();

    fn try_from(value: &TwccSendRecord) -> Result<Self, Self::Error> {
        let Some(remote_recv_time) = value.remote_recv_time() else {
            return Err(());
        };

        Ok(Self {
            seq_no: value.seq(),
            local_send_time: value.local_send_time(),
            remote_recv_time,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BandwithUsage {
    Overuse,
    Normal,
    Underuse,
}

impl fmt::Display for BandwithUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BandwithUsage::Overuse => write!(f, "overuse"),
            BandwithUsage::Normal => write!(f, "normal"),
            BandwithUsage::Underuse => write!(f, "underuse"),
        }
    }
}
