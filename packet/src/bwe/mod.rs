mod arrival_group;
pub(crate) mod macros;
mod rate_control;
mod trendline_estimator;

use std::fmt;
use std::time::Instant;

use arrival_group::{ArrivalGroupAccumulator, InterGroupDelayVariation};
use rate_control::RateControl;
use rtp::{Bitrate, SeqNo, TwccSendRecord};
use trendline_estimator::TrendlineEstimator;

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
    last_estimate: Option<Bitrate>,
}

impl SendSideBandwithEstimator {
    pub fn new(initial_bitrate: Bitrate) -> Self {
        Self {
            arrival_group_accumulator: ArrivalGroupAccumulator::default(),
            trendline_estimator: TrendlineEstimator::new(20),
            rate_control: RateControl::new(initial_bitrate, 40_000.into(), Bitrate::gbps(10)),
            last_estimate: None,
        }
    }

    /// Record a packet from a TWCC report.
    pub fn update(&mut self, records: &[&TwccSendRecord], observed_bitrate: Bitrate, now: Instant) {
        for record in records {
            let Ok(acked_packet) = (*record).try_into() else {
                continue;
            };

            if let Some(delay_variation) = self
                .arrival_group_accumulator
                .accumulate_packet(acked_packet)
            {
                crate::bwe::macros::log_delay_variation!(delay_variation.delay);

                // Got a new delay variation, add it to the trendline
                self.trendline_estimator
                    .add_delay_observation(delay_variation, now);
            }
        }

        let new_hypothesis = self.trendline_estimator.hypothesis();

        self.rate_control
            .update(new_hypothesis.into(), observed_bitrate, now);
        let estimated_rate = self.rate_control.estimated_bitrate();

        crate::bwe::macros::log_bitrate_estimate!(estimated_rate.as_f64());
        self.last_estimate = Some(estimated_rate);
    }

    pub fn update_rtt(&mut self, rtt_us: f64) {
        self.rate_control.update_rtt(rtt_us);
    }

    pub fn poll_estimate(&mut self) -> Option<Bitrate> {
        self.last_estimate.take()
    }

    pub fn set_is_probing(&mut self, is_probing: bool, now: Instant) {
        self.rate_control.set_is_probing(is_probing, now);
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
